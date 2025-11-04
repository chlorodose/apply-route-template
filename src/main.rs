use std::{
    collections::HashMap,
    env,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    pin::pin,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};

use cidr::{AnyIpCidr, Ipv4Cidr, Ipv6Cidr};
use futures::{FutureExt, StreamExt};
use rtnetlink::{
    MulticastGroup, RouteHandle, RouteMessageBuilder, new_multicast_connection,
    packet_core::NetlinkPayload,
    packet_route::{
        RouteNetlinkMessage,
        route::{RouteAddress, RouteAttribute, RouteMessage},
    },
};
use systemd::daemon::{STATE_READY, STATE_RELOADING, STATE_STATUS, notify as systemd_notify};
use tokio::{
    sync::Notify,
    time::{Instant, sleep},
};

type GeoItem = (Vec<Ipv4Cidr>, Vec<Ipv6Cidr>);

static IN_ERR: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() {
    assert!(
        systemd_notify(false, [(STATE_STATUS, "initializing..."),].iter(),).unwrap(),
        "notify systemd failed"
    );
    let (task, handle, mut chan) =
        new_multicast_connection(&[MulticastGroup::Ipv4Route, MulticastGroup::Ipv6Route])
            .expect("failed to connect to netlink");
    tokio::spawn(task);
    let handle = handle.route();
    let geoip_path = env::var_os("GEOIP_PATH")
        .map(PathBuf::from)
        .expect("geoip path not given");
    eprintln!("Loding config");
    let map: &HashMap<IpAddr, GeoItem> = Box::leak(Box::new(
        serde_json::from_reader::<_, HashMap<IpAddr, String>>(
            std::fs::File::open(env::var("MAP_FILE").expect("failed to open map file"))
                .expect("failed to open config"),
        )
        .expect("failed to parse map file")
        .into_iter()
        .map(|(k, v)| (k, read_geoip(&v, &geoip_path)))
        .collect(),
    ));
    let from_table: u8 = str::parse(&env::var("FROM_TABLE").expect("FROM_TABLE not given"))
        .expect("FROM_TABLE is not an valid table num");
    let to_table: u8 = str::parse(&env::var("TO_TABLE").unwrap_or("254".to_string()))
        .expect("TO_TABLE is not an valid table num");

    let notify = Arc::new(Notify::new());
    eprintln!("Starting update thread");
    tokio::spawn(update_thread(
        Arc::clone(&notify),
        handle,
        from_table,
        to_table,
        map,
    ));

    loop {
        let msg = chan.next().await.unwrap();
        if !matches!(
            msg.0.payload,
            NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::DelRoute(_) | RouteNetlinkMessage::NewRoute(_),
            )
        ) {
            continue;
        }
        notify.notify_one();
    }
}
async fn update_thread(
    notify: Arc<Notify>,
    handle: RouteHandle,
    from_table: u8,
    to_table: u8,
    map: &'static HashMap<IpAddr, GeoItem>,
) {
    loop {
        update(handle.clone(), from_table, to_table, map).await;
        assert!(
            systemd_notify(
                false,
                [
                    (STATE_READY, "1"),
                    (STATE_STATUS, "done, waiting for network changes"),
                ]
                .iter(),
            )
            .unwrap(),
            "notify systemd failed"
        );
        notify.notified().await;
        assert!(
            systemd_notify(
                false,
                [
                    (STATE_RELOADING, "1"),
                    (STATE_STATUS, "reloading due to network changes"),
                ]
                .iter(),
            )
            .unwrap(),
            "notify systemd failed"
        );
        loop {
            eprintln!("Recv network changes, waiting 100ms for more changes to come...");
            sleep(Duration::from_millis(100)).await;
            if pin!(notify.notified())
                .poll_unpin(&mut Context::from_waker(Waker::noop()))
                .is_pending()
            {
                break;
            }
        }
    }
}
async fn update(
    handle: RouteHandle,
    from_table: u8,
    to_table: u8,
    map: &'static HashMap<IpAddr, GeoItem>,
) {
    let start_time = Instant::now();
    eprintln!("Flushing routes");
    IN_ERR.store(false, Ordering::Relaxed);
    loop {
        let stream = futures::stream::select(
            handle
                .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
                .execute(),
            handle
                .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
                .execute(),
        );
        stream
            .for_each_concurrent(None, async |r| {
                let Ok(m) = r else {
                    return;
                };
                if m.header.table != to_table {
                    return;
                }
                let result = handle.del(m).execute().await;
                if let Err(err) = result {
                    eprintln!("Error: {err}");
                }
            })
            .await;
        if !IN_ERR.load(Ordering::Relaxed) {
            break;
        }
    }

    eprintln!("Translating Routes");
    IN_ERR.store(false, Ordering::Relaxed);
    let sum = loop {
        let stream = futures::stream::select(
            handle
                .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
                .execute(),
            handle
                .get(RouteMessageBuilder::<Ipv6Addr>::new().build())
                .execute(),
        );
        let stream: Vec<_> = stream
            .filter_map(async |r| {
                let Ok(mut m) = r else {
                    return None;
                };
                if m.header.table != from_table {
                    return None;
                }
                m.header.table = to_table;
                m.attributes = m
                    .attributes
                    .iter()
                    .filter(|e| !matches!(e, RouteAttribute::Table(_)))
                    .cloned()
                    .collect();
                m.attributes
                    .push(RouteAttribute::Table(u32::from(to_table)));
                Some(tokio::spawn(try_map(map, handle.clone(), m)))
            })
            .collect()
            .await;
        let mut sum = 0;
        for task in stream {
            sum += task.await.unwrap();
        }
        if !IN_ERR.load(Ordering::Relaxed) {
            break sum;
        }
    };
    eprintln!(
        "Done, added {sum} routes, tooks {}ms",
        Instant::now().duration_since(start_time).as_millis()
    );
}
fn read_geoip(name: &str, geoip_path: impl AsRef<Path>) -> GeoItem {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    name.split('+').for_each(|name| match name {
        "default" => {
            v4.push(Ipv4Cidr::new(Ipv4Addr::from_bits(0), 0).unwrap());
            v6.push(Ipv6Cidr::new(Ipv6Addr::from_bits(0), 0).unwrap());
        }
        body => read_to_string(geoip_path.as_ref().join(format!("{body}.txt")))
            .expect("unable to open geoip file")
            .lines()
            .for_each(|s| {
                let cidr = AnyIpCidr::from_str(s);
                match cidr {
                    Ok(AnyIpCidr::V4(cidr)) => v4.push(cidr),
                    Ok(AnyIpCidr::V6(cidr)) => v6.push(cidr),
                    _ => (),
                }
            }),
    });
    (v4, v6)
}
async fn try_map(
    map: &HashMap<IpAddr, GeoItem>,
    handle: RouteHandle,
    source: RouteMessage,
) -> usize {
    let mut tasks = Vec::new();
    source.attributes.iter().enumerate().find(|(i, e)| match e {
        RouteAttribute::Destination(RouteAddress::Inet(addr)) => {
            let Some(mat) = map.get(&IpAddr::V4(*addr)) else {
                return true;
            };
            for cidr in &mat.0 {
                let mut msg = source.clone();
                msg.attributes[*i] =
                    RouteAttribute::Destination(RouteAddress::Inet(cidr.first_address()));
                msg.header.destination_prefix_length = cidr.network_length();
                tasks.push(tokio::spawn(handle.add(msg).execute()));
            }
            true
        }
        RouteAttribute::Destination(RouteAddress::Inet6(addr)) => {
            let Some(mat) = map.get(&IpAddr::V6(*addr)) else {
                return false;
            };
            for cidr in &mat.1 {
                let mut msg = source.clone();
                msg.attributes[*i] =
                    RouteAttribute::Destination(RouteAddress::Inet6(cidr.first_address()));
                msg.header.destination_prefix_length = cidr.network_length();
                tasks.push(tokio::spawn(handle.add(msg).execute()));
            }
            true
        }
        _ => false,
    });
    let len = tasks.len();
    for h in tasks {
        let result = h.await.unwrap();
        if let Err(err) = result {
            eprintln!("Error: {err}");
            IN_ERR.store(true, Ordering::Relaxed);
        }
    }
    len
}
