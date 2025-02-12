### Cluster Mask

```cpp
struct Connection {
    uint32_t id;
    C_Type type;
    uint32_t params;
    std::atomic<bool> alive;
    std::optional<std::string> destination_cluster_mask;
};
```
<br/>

### Mask structure `Users`
```
user_name@cluster
```
<br/>

Examples
```
akzestia@cx-xa-zw
```
```
zuru@uu-si-xo
```
```
azure@yk-nq-x8
```
<br/>

### Mask structure `Global Services`
```
service@zurui
```
<br/>

Examples
```
authentication@zurui
```
```
cluster_selection@zurui
```
<br/>

### Mask structure `Cluster Specific Services`
```
service@cluster
```
<br/>

Examples
```
status@cx-xa-zw
```
```
media@cx-xa-zw
```
```
archive@cx-xa-zw
```
