'''
 # @ Create Time: 2024-09-02 14:01:51
 # @ Modified time: 2024-09-02 14:03:32
 # @ Description: load from csv for node and edge with their attributes

potential methods to explore for concating features together
    (1) element-wise operations
        + or *
    (2) matrix multiplication
        torch.mm
    (3) stack
        torch.stack
    (4) linear combination
        weight_x * x + weight_attr * attr
    (5) attention mechanism
    (6) hadamard product
        element-wise multiplication followed by a sum reduction or another operation

 '''

import torch
import pandas as pd


def load_node_csv(path, index_col, encoders=None, **kwargs):
    ''' encode node value and node attributes
    
    '''
    df = pd.read_csv(path, index_col=index_col, **kwargs)
    mapping = {index: i for i, index in enumerate(df.index.unique())}

    # encode node feature (x)
    x = None
    if encoders is not None:
        xs = [encoder(df[col]) for col, encoder in encoders.items()]
        # first try with basic concat
        x = torch.cat(xs, dim=-1)

    return x, mapping


def load_edge_csv(path, src_index_col, src_mapping, dst_index_col, dst_mapping,
                encoders=None, **kwargs):
    ''' encode edge value and edge attributes
    
    '''
    df = pd.read_csv(path, **kwargs)

    src = [df[src_mapping[index]] for index in df[src_index_col]]
    dst = [df[dst_mapping[index]] for index in df[dst_index_col]]
    edge_index = torch.tensor([src, dst])

    # encode node attributes
    edge_attrs = None
    if encoders is not None:
        edge_attrs = [ encoder(df[col])  for col, encoder in encoders.items()]
        # first try with basic concat
        edge_attr = torch.cat(edge_attrs, dim=-1)

    return edge_index, edge_attr

if __name__ == "__main__":
    pass