use std::{
    collections::HashMap,
    env,
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    process::exit,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use cidr::{AnyIpCidr, Ipv4Cidr, Ipv6Cidr};
use futures::StreamExt;
use rtnetlink::{
    RouteHandle, RouteMessageBuilder,
    packet_route::route::{RouteAddress, RouteAttribute, RouteMessage},
};

static DONE_NUM: AtomicU64 = AtomicU64::new(0);
static ERR_NUM: AtomicU64 = AtomicU64::new(0);

type GeoItem = (Vec<Ipv4Cidr>, Vec<Ipv6Cidr>);

#[tokio::main]
async fn main() {
    let (task, handle, _) = rtnetlink::new_connection().expect("failed to connect to netlink");
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

    eprintln!("Flushing routes");
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

    eprintln!("Translating Routes");
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
            let Ok(mut m) = r else {
                return;
            };
            if m.header.table != from_table {
                return;
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
            tokio::spawn(try_map(map, handle.clone(), m)).await.unwrap();
        })
        .await;
    eprintln!(
        "Done, added {} routes, {} failed",
        DONE_NUM.load(Ordering::Relaxed),
        ERR_NUM.load(Ordering::Relaxed)
    );
    if ERR_NUM.load(Ordering::Relaxed) != 0 {
        exit(1);
    }
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
async fn try_map(map: &HashMap<IpAddr, GeoItem>, handle: RouteHandle, source: RouteMessage) {
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
    for h in tasks {
        let result = h.await.unwrap();
        if let Err(err) = result {
            eprintln!("Error: {err}");
            &ERR_NUM
        } else {
            &DONE_NUM
        }
        .fetch_add(1, Ordering::Relaxed);
    }
}
