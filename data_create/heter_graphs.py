'''
 # @ Create Time: 2024-08-12 11:13:13
 # @ Modified time: 2024-08-19 15:16:15
 # @ Description: module to create hetergenous graphs with mutiple edge/node 
 attributesfrom csv or parquet
 ''' 

from torch_geometric.data import HeteroData, Data, TemporalData, InMemoryDataset

def load_node_csv(node_csv):
    


def load_edge_csv(edge_csv):



def static_graph_load(node_csv, edge_csv):
    ''' create hetergenous dataset from csv, the csv follows certain patterns
    node_csv: node, attr1, attr2, ...
    edge_csv: source, dest, attr1, attr2, ...
    
    return: pytorch graph dataset 
    '''
    data = HeteroData()

    # define node features [num_{node_type}, num_feature_{node_type}]
    ## define node type 
    data['node_type_x'].x =
    data['node_type_y'].x =
    data['node_type_z'].x =


    # define edges [2, num_{edge_type}]
    data['node_type_x', 'edge_type_y', 'node_type_z'].edge_index =

    # define edges attributes [num_{edge_type}, num_features_{edge_type}]
    data["node_type_x", 'edge_type_y', 'node_type_z'].edge_attr = 


    # set attributes
    data["node_type_x"].attr1= 


def temp_graph_load():
