from torch.geometric.data import HeteroData

data = HeteroData()

# define node features [num_{node_type}, num_feature_{node_type}]
## define node type 
data['node_type_x'].x =
data['node_type_y'].x =
data['node_type_z'].x =


# define edges [2, num_edge_type]
data['node_type_x', 'edge_type_y', 'node_type_z'].edge_index =

# define edges attributes [num_edge_type, num_features_{edge_type}]
data["node_type_x", 'edge_type_y', 'node_type_z'].edge_attr = 