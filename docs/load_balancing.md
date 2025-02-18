# Load Balancing

## Centralized Load Balancing

### Pros
- **Reliability**
- **High throughput**
- **No direct IP exposure** to the DNS provider
- **Cheaper price per cluster** (No need for cluster-specific load balancers)

### Cons
- **Higher upfront cost** (for me ^_^)
- **Single point of failure** (Even though we have multiple load balancers, if they all fail, it will lead to downtime)

## Why NOT to Use Subdomains

### Simple, Privacy.

### Pros

- **Easier Management per Cluster**:  
  Subdomains allow you to isolate each cluster, making it simpler to manage configurations, updates, and troubleshooting on a per-cluster basis.

- **Easier Implementation**:  
  Setting up load balancing with subdomains can be more straightforward, especially if your architecture already leverages DNS-based routing. This reduces the need for complex internal routing mechanisms.

- **Simpler Rulesets for Cross-Cluster Communication**:  
  With distinct subdomains, creating and managing rules for communication between clusters becomes clearer and more intuitive. Each service or cluster can be directly addressed, which can simplify configuration.

### Cons

- **Balancer's IP Exposure to the DNS Provider**:  
  One of the major drawbacks is that the IP addresses of your load balancers become exposed to the DNS provider. This exposure can lead to potential privacy concerns and may increase the risk of targeted attacks.

- **Increased Risk of Misconfiguration**:  
  Managing multiple subdomains can lead to configuration errors. A small mistake in DNS settings or load balancer configurations might cause unexpected downtime or misrouted traffic.

- **Limited Flexibility in Dynamic Scaling**:  
  While subdomains simplify certain aspects of management, they may not easily adapt to rapid changes in demand. Centralized load balancing solutions can offer more dynamic scaling options compared to the more static nature of subdomain assignments.
