// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Clustering support for log fingerprinting.
//!
//! This module implements Jaccard-similarity based clustering compatible with
//! the Go implementation in oteltools/pkg/fingerprinter/trie_cluster_manager.go.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, Mutex};
use std::time::Instant;

use xxhash_rust::xxh64::xxh64;

/// Compute Jaccard similarity between two token sets.
///
/// Jaccard(A, B) = |A ∩ B| / |A ∪ B|
pub fn jaccard_similarity(set1: &HashSet<String>, set2: &HashSet<String>) -> f64 {
    let intersection = set1.intersection(set2).count();
    let union = set1.len() + set2.len() - intersection;
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// A cluster of similar log messages.
#[derive(Debug)]
pub struct Cluster {
    /// The fingerprint value for this cluster.
    pub fingerprint: i64,
    /// Set of tokens seen in this cluster (intersection over time).
    pub token_set: HashSet<String>,
    /// Number of logs that matched this cluster.
    pub match_count: usize,
    /// Total number of match attempts.
    pub total: usize,
    /// Last time this cluster was updated.
    pub last_updated: Instant,
}

impl Cluster {
    /// Create a new cluster with the given fingerprint and initial token set.
    pub fn new(fingerprint: i64, tokens: HashSet<String>) -> Self {
        Self {
            fingerprint,
            token_set: tokens,
            match_count: 1,
            total: 1,
            last_updated: Instant::now(),
        }
    }

    /// Get the match rate for this cluster.
    pub fn match_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.match_count as f64 / self.total as f64
        }
    }

    /// Record a match attempt.
    ///
    /// If matched, intersects the token set with incoming tokens.
    pub fn record(&mut self, incoming: &HashSet<String>, matched: bool) {
        if matched {
            // Intersect token sets - keep only common tokens
            self.token_set = self.token_set.intersection(incoming).cloned().collect();
            self.match_count += 1;
        }
        self.total += 1;
        self.last_updated = Instant::now();
    }
}

/// Manages clusters at a trie leaf node.
#[derive(Debug)]
pub struct LeafClusterer {
    /// Jaccard similarity threshold for matching.
    threshold: f64,
    /// Clusters sorted by match rate (descending).
    clusters: Vec<Cluster>,
}

impl LeafClusterer {
    /// Create a new leaf clusterer with the given similarity threshold.
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            clusters: Vec::new(),
        }
    }

    /// Add a token sequence to this leaf, returning the cluster fingerprint.
    ///
    /// If a matching cluster exists (Jaccard >= threshold), returns its fingerprint.
    /// Otherwise creates a new cluster.
    pub fn add(&mut self, tokens: &[String], json_keys: &[String]) -> i64 {
        let incoming: HashSet<String> = tokens.iter().cloned().collect();

        // Try to match existing clusters
        let mut matched_idx: Option<usize> = None;
        for (idx, cluster) in self.clusters.iter_mut().enumerate() {
            let score = jaccard_similarity(&cluster.token_set, &incoming);
            cluster.record(&incoming, score >= self.threshold);

            if score >= self.threshold && matched_idx.is_none() {
                matched_idx = Some(idx);
            }
        }

        if let Some(idx) = matched_idx {
            let fp = self.clusters[idx].fingerprint;
            // Bubble up by match rate
            self.bubble_up(idx);
            return fp;
        }

        // No match - create new cluster
        let fp = compute_fingerprint(tokens, json_keys);
        let cluster = Cluster::new(fp, incoming);
        self.clusters.insert(0, cluster);
        fp
    }

    /// Get all clusters in this leaf.
    pub fn clusters(&self) -> &[Cluster] {
        &self.clusters
    }

    /// Get mutable access to clusters.
    pub fn clusters_mut(&mut self) -> &mut Vec<Cluster> {
        &mut self.clusters
    }

    /// Get the threshold for this clusterer.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Bubble up a cluster by match rate.
    fn bubble_up(&mut self, idx: usize) {
        let mut i = idx;
        while i > 0 && self.clusters[i].match_rate() > self.clusters[i - 1].match_rate() {
            self.clusters.swap(i, i - 1);
            i -= 1;
        }
    }
}

/// A node in the trie structure.
pub struct TrieNode {
    /// Children keyed by token string.
    children: RwLock<HashMap<String, Arc<TrieNode>>>,
    /// Leaf clusterer at this node (if any).
    leaf: Mutex<Option<LeafClusterer>>,
}

impl TrieNode {
    /// Create a new empty trie node.
    pub fn new() -> Self {
        Self {
            children: RwLock::new(HashMap::new()),
            leaf: Mutex::new(None),
        }
    }

    /// Get or create a child node for the given token.
    pub fn get_or_create_child(self: &Arc<Self>, token: &str) -> Arc<TrieNode> {
        // First try read lock
        {
            let children = self.children.read().unwrap();
            if let Some(child) = children.get(token) {
                return Arc::clone(child);
            }
        }

        // Need to create - use write lock
        let mut children = self.children.write().unwrap();
        children
            .entry(token.to_string())
            .or_insert_with(|| Arc::new(TrieNode::new()))
            .clone()
    }

    /// Try to get an existing child node.
    pub fn get_child(&self, token: &str) -> Option<Arc<TrieNode>> {
        let children = self.children.read().unwrap();
        children.get(token).cloned()
    }

    /// Collect all leaf clusterers under this node (DFS).
    pub fn collect_leaves(self: &Arc<Self>) -> Vec<Arc<TrieNode>> {
        let mut leaves = Vec::new();
        self.collect_leaves_recursive(&mut leaves);
        leaves
    }

    fn collect_leaves_recursive(self: &Arc<Self>, leaves: &mut Vec<Arc<TrieNode>>) {
        // Check if this node has a leaf
        {
            let leaf = self.leaf.lock().unwrap();
            if leaf.is_some() {
                leaves.push(Arc::clone(self));
            }
        }

        // Recurse into children
        let children = self.children.read().unwrap();
        for child in children.values() {
            child.collect_leaves_recursive(leaves);
        }
    }
}

impl Default for TrieNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Trie-based cluster manager for log fingerprinting.
///
/// Maps token prefixes to clusters using a trie structure.
/// Similar logs (by Jaccard similarity) share the same fingerprint.
pub struct TrieClusterManager {
    /// Root of the trie.
    root: Arc<TrieNode>,
    /// Jaccard similarity threshold.
    threshold: f64,
}

impl TrieClusterManager {
    /// Create a new cluster manager with the given similarity threshold.
    ///
    /// Typical values: 0.5 for loose clustering, 0.8 for strict.
    pub fn new(threshold: f64) -> Self {
        Self {
            root: Arc::new(TrieNode::new()),
            threshold,
        }
    }

    /// Cluster a token sequence, returning the fingerprint.
    ///
    /// Algorithm:
    /// 1. Walk the trie following the token sequence
    /// 2. If exact match: use leaf clusterer at that node
    /// 3. If diverged: scan subtree for best Jaccard match
    /// 4. If no match found: create new branch and cluster
    pub fn cluster(&self, tokens: &[String], json_keys: &[String]) -> i64 {
        let mut current = Arc::clone(&self.root);
        let mut i = 0;

        // Walk trie as far as possible
        while i < tokens.len() {
            match current.get_child(&tokens[i]) {
                Some(next) => {
                    current = next;
                    i += 1;
                }
                None => break,
            }
        }

        // Exact match - use leaf at current node
        if i == tokens.len() {
            return self.add_to_leaf(&current, tokens, json_keys);
        }

        // Diverged - scan subtree for best Jaccard match
        let incoming: HashSet<String> = tokens.iter().cloned().collect();

        if let Some(fp) = self.find_best_match(&current, &incoming) {
            return fp;
        }

        // No match - create new branch for remaining tokens
        for token in &tokens[i..] {
            current = current.get_or_create_child(token);
        }

        self.add_to_leaf(&current, tokens, json_keys)
    }

    /// Add to the leaf clusterer at the given node.
    fn add_to_leaf(&self, node: &Arc<TrieNode>, tokens: &[String], json_keys: &[String]) -> i64 {
        let mut leaf = node.leaf.lock().unwrap();
        if leaf.is_none() {
            *leaf = Some(LeafClusterer::new(self.threshold));
        }
        leaf.as_mut().unwrap().add(tokens, json_keys)
    }

    /// Find best matching cluster in subtree using Jaccard similarity.
    fn find_best_match(&self, node: &Arc<TrieNode>, incoming: &HashSet<String>) -> Option<i64> {
        let leaves = node.collect_leaves();

        let mut best_score = -1.0f64;
        let mut best_fp: Option<i64> = None;
        let mut best_node: Option<Arc<TrieNode>> = None;

        for leaf_node in &leaves {
            let leaf_guard = leaf_node.leaf.lock().unwrap();

            if let Some(ref leaf) = *leaf_guard {
                for cluster in leaf.clusters() {
                    let score = jaccard_similarity(&cluster.token_set, incoming);
                    if score >= leaf.threshold() && score > best_score {
                        best_score = score;
                        best_fp = Some(cluster.fingerprint);
                        best_node = Some(Arc::clone(leaf_node));
                    }
                }
            }
        }

        // If we found a match, update the cluster
        if let (Some(fp), Some(node)) = (best_fp, best_node) {
            let mut leaf_guard = node.leaf.lock().unwrap();
            if let Some(ref mut leaf) = *leaf_guard {
                // Find the cluster and record the match
                for cluster in leaf.clusters_mut() {
                    if cluster.fingerprint == fp {
                        cluster.record(incoming, true);
                        break;
                    }
                }
            }
            return Some(fp);
        }

        None
    }
}

/// Compute fingerprint from tokens and JSON keys.
pub fn compute_fingerprint(tokens: &[String], json_keys: &[String]) -> i64 {
    let mut combined = tokens.join(":");
    for key in json_keys {
        combined.push(':');
        combined.push_str(key);
    }
    xxh64(combined.as_bytes(), 0) as i64
}

/// Manages TrieClusterManagers per tenant (organization).
///
/// Each tenant gets their own trie to ensure:
/// - Isolation between tenants
/// - Memory containment per tenant
/// - Independent clustering patterns
pub struct TenantManager {
    /// Map of tenant_id -> TrieClusterManager
    tenants: RwLock<HashMap<String, Arc<TrieClusterManager>>>,
    /// Default Jaccard similarity threshold for new tenants
    threshold: f64,
}

impl TenantManager {
    /// Create a new tenant manager with the given default threshold.
    pub fn new(threshold: f64) -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
            threshold,
        }
    }

    /// Get the TrieClusterManager for a tenant, creating one if needed.
    pub fn get_or_create(&self, tenant_id: &str) -> Arc<TrieClusterManager> {
        // Try read lock first
        {
            let tenants = self.tenants.read().unwrap();
            if let Some(cm) = tenants.get(tenant_id) {
                return Arc::clone(cm);
            }
        }

        // Need to create - use write lock
        let mut tenants = self.tenants.write().unwrap();
        tenants
            .entry(tenant_id.to_string())
            .or_insert_with(|| Arc::new(TrieClusterManager::new(self.threshold)))
            .clone()
    }

    /// Get the number of tenants currently tracked.
    pub fn tenant_count(&self) -> usize {
        self.tenants.read().unwrap().len()
    }

    /// Remove a tenant's cluster manager (for cleanup/eviction).
    pub fn remove_tenant(&self, tenant_id: &str) -> bool {
        self.tenants.write().unwrap().remove(tenant_id).is_some()
    }

    /// List all tenant IDs.
    pub fn tenant_ids(&self) -> Vec<String> {
        self.tenants.read().unwrap().keys().cloned().collect()
    }
}

/// Global tenant manager for log fingerprinting.
///
/// Uses a default threshold of 0.5 for Jaccard similarity clustering.
pub static TENANT_MANAGER: once_cell::sync::Lazy<TenantManager> =
    once_cell::sync::Lazy::new(|| TenantManager::new(0.5));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_similarity_identical() {
        let set1: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let set2: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        assert!((jaccard_similarity(&set1, &set2) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_jaccard_similarity_disjoint() {
        let set1: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let set2: HashSet<String> = ["c", "d"].iter().map(|s| s.to_string()).collect();
        assert!((jaccard_similarity(&set1, &set2) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_jaccard_similarity_partial() {
        let set1: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let set2: HashSet<String> = ["b", "c", "d"].iter().map(|s| s.to_string()).collect();
        // intersection = {b, c} = 2, union = {a, b, c, d} = 4
        assert!((jaccard_similarity(&set1, &set2) - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_jaccard_similarity_empty() {
        let set1: HashSet<String> = HashSet::new();
        let set2: HashSet<String> = HashSet::new();
        assert!((jaccard_similarity(&set1, &set2) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cluster_match_rate() {
        let mut cluster = Cluster::new(123, HashSet::new());
        assert!((cluster.match_rate() - 1.0).abs() < 0.001);

        let incoming = HashSet::new();
        cluster.record(&incoming, false);
        assert!((cluster.match_rate() - 0.5).abs() < 0.001);

        cluster.record(&incoming, true);
        assert!((cluster.match_rate() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_compute_fingerprint() {
        let tokens = vec!["hello".to_string(), "world".to_string()];
        let json_keys = vec!["key1".to_string()];
        let fp = compute_fingerprint(&tokens, &json_keys);
        assert_ne!(fp, 0);

        // Same input should produce same fingerprint
        let fp2 = compute_fingerprint(&tokens, &json_keys);
        assert_eq!(fp, fp2);
    }
}
