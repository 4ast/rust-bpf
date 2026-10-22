// SPDX-License-Identifier: GPL-2.0
//! crates: petgraph, priority-queue
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Reverse;
use core::hash::BuildHasherDefault;
use petgraph::Direction;
use petgraph::data::FromElements;
use petgraph::algo::{connected_components, dijkstra, has_path_connecting, is_cyclic_directed, kosaraju_scc, toposort};
use petgraph::graph::{DiGraph, NodeIndex, UnGraph};
use petgraph::graphmap::GraphMap;
use petgraph::visit::{Bfs, Dfs, EdgeRef};
use rt::{bb, check, check_eq, test};

fn diamond() -> (DiGraph<&'static str, u32>, [NodeIndex; 5]) {
    let mut g = DiGraph::new();
    let n = ["a", "b", "c", "d", "e"].map(|w| g.add_node(w));
    g.extend_with_edges([(n[0], n[1], bb(7)), (n[0], n[2], 2), (n[2], n[1], 3), (n[1], n[3], 1), (n[2], n[3], 8), (n[3], n[4], 5)]);
    (g, n)
}

test!(petgraph_build, {
    let (mut g, n) = diamond();
    check_eq!(g.node_count(), 5);
    check_eq!(g.edge_count(), 6);
    check_eq!(g[n[2]], "c");
    check_eq!(g.neighbors(n[0]).count(), 2);
    check_eq!(g.neighbors_directed(n[3], Direction::Incoming).count(), 2);
    check_eq!(g.edges(n[2]).map(|e| *e.weight()).sum::<u32>(), 11);
    let e = g.find_edge(n[0], n[2]).unwrap();
    check_eq!(g[e], 2);
    check_eq!(g.edge_endpoints(e), Some((n[0], n[2])));
    check!(g.find_edge(n[2], n[0]).is_none());
    check!(g.contains_edge(n[3], n[4]));
    *g.edge_weight_mut(e).unwrap() = 20;
    check_eq!(g.edge_weights().sum::<u32>(), 44);
    check_eq!(g.remove_edge(e), Some(20));
    check_eq!(g.remove_node(n[4]), Some("e"));
    check!(g.node_count() == 4 && g.edge_count() == 4);
    check_eq!(g.externals(Direction::Outgoing).count(), 1);
});

test!(petgraph_dijkstra, {
    let (g, n) = diamond();
    let d = dijkstra(&g, n[0], None, |e| *e.weight());
    check_eq!(d[&n[0]], 0);
    check_eq!(d[&n[1]], 5);
    check_eq!(d[&n[2]], 2);
    check_eq!(d[&n[3]], 6);
    check_eq!(d[&n[4]], 11);
    let back = dijkstra(&g, n[4], None, |e| *e.weight());
    check_eq!(back.len(), 1);
});

test!(petgraph_traversal, {
    let (g, n) = diamond();
    let mut bfs = Bfs::new(&g, n[0]);
    let mut order = Vec::new();
    while let Some(x) = bfs.next(&g) {
        order.push(g[x]);
    }
    check_eq!(order.len(), 5);
    check!(order[0] == "a" && order[4] == "e");
    let mut dfs = Dfs::new(&g, n[2]);
    let mut seen = 0;
    while dfs.next(&g).is_some() {
        seen += 1;
    }
    check_eq!(seen, 4);
    check!(has_path_connecting(&g, n[0], n[4], None));
    check!(!has_path_connecting(&g, n[4], n[0], None));
});

test!(petgraph_toposort_scc, {
    let (mut g, n) = diamond();
    check!(!is_cyclic_directed(&g));
    let t = toposort(&g, None).unwrap();
    let pos = |x: NodeIndex| t.iter().position(|y| *y == x).unwrap();
    check!(g.edge_references().all(|e| pos(e.source()) < pos(e.target())));
    check_eq!(kosaraju_scc(&g).len(), 5);
    g.add_edge(n[3], n[0], bb(1));
    check!(is_cyclic_directed(&g));
    check!(toposort(&g, None).is_err());
    let scc = kosaraju_scc(&g);
    check_eq!(scc.len(), 2);
    check_eq!(scc.iter().map(|c| c.len()).max(), Some(4));
});

test!(petgraph_undirected, {
    let mut g: UnGraph<u32, ()> = UnGraph::new_undirected();
    let n: Vec<NodeIndex> = (0..bb(8)).map(|i| g.add_node(i)).collect();
    for (a, b) in [(0, 1), (1, 2), (3, 4), (5, 6), (6, 7), (7, 5)] {
        g.add_edge(n[a], n[b], ());
    }
    check_eq!(connected_components(&g), 3);
    check_eq!(g.neighbors(n[1]).count(), 2);
    check_eq!(g.neighbors(n[6]).count(), 2);
    g.add_edge(n[2], n[3], ());
    check_eq!(connected_components(&g), 2);
    let m = petgraph::algo::min_spanning_tree(&g);
    let t: UnGraph<u32, ()> = UnGraph::from_elements(m);
    check_eq!(t.edge_count(), 6);
});

test!(petgraph_graphmap, {
    let mut g: GraphMap<u32, u32, petgraph::Directed, BuildHasherDefault<fnv::FnvHasher>> = GraphMap::default();
    g.add_edge(bb(1), 2, 10);
    g.add_edge(2, 3, 20);
    g.add_edge(1, 3, 50);
    check!(g.node_count() == 3 && g.edge_count() == 3);
    check_eq!(g.edge_weight(1, 3), Some(&50));
    check!(g.contains_edge(2, 3) && !g.contains_edge(3, 2));
    check_eq!(g.neighbors(1).sum::<u32>(), 5);
    let d = dijkstra(&g, 1, Some(3), |e| *e.weight());
    check_eq!(d[&3], 30);
    check!(g.remove_node(2));
    check_eq!(g.edge_count(), 1);
});

type Pq<I, P> = priority_queue::PriorityQueue<I, P, BuildHasherDefault<fnv::FnvHasher>>;

test!(priority_queue_ops, {
    let mut q: Pq<&str, u32> = Pq::with_default_hasher();
    check_eq!(q.push(bb("low"), 1), None);
    q.push("high", 10);
    q.push("mid", 5);
    check_eq!(q.len(), 3);
    check_eq!(q.peek(), Some((&"high", &10)));
    check_eq!(q.change_priority("low", 20), Some(1));
    check_eq!(q.peek(), Some((&"low", &20)));
    check_eq!(q.get_priority("mid"), Some(&5));
    check_eq!(q.push("mid", 30), Some(5));
    check_eq!(q.push_increase("mid", 3), Some(3));
    check_eq!(q.pop(), Some(("mid", 30)));
    check_eq!(q.remove("high"), Some(("high", 10)));
    check_eq!(q.pop(), Some(("low", 20)));
    check_eq!(q.pop(), None);
});

test!(priority_queue_sorted, {
    let mut q: Pq<u32, Reverse<u32>> = Pq::with_default_hasher();
    for i in 0..bb(100u32) {
        q.push(i, Reverse((i * 37) % 101));
    }
    let v: Vec<u32> = q.into_sorted_iter().map(|(_, p)| p.0).collect();
    check!(v.len() == 100 && v.is_sorted());
});
