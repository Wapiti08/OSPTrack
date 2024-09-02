'''
 # @ Create Time: 2024-08-19 09:51:24
 # @ Modified time: 2024-08-19 09:51:45
 # @ Description: diverse data loading methods
 '''
import networkx as nx
import pandas as pd


def conv_dict_cols(df, column):
    ''' convert dict type to separate columns
    
    '''
    # check if all dictionary values are empty
    all_empty=all([not bool(d) for d in df[column]])
    if not all_empty:
        # extract all the keys that appear in any of the dictionaries
        all_keys = set().union(*(d.keys() for d in df[column] if d))

        # create new columns for each key
        for key in all_keys:
            df[key] = df[column].apply(lambda x: x.get(key)).astype(str)

    # remove original Node_Attrs
    df = df.drop(columns=[column])

    return df


def graphml_csv(graph_path:str):
    G = nx.read_graphml(graph_path)

    # convert nodes to DataFrame
    nodes_df = pd.DataFrame(list(G.nodes(data=True)))
    nodes_df.columns = ["Node", "Node_Attrs"]
    nodes_df = conv_dict_cols(nodes_df, "Node_Attrs")    

    # convert edges to DataFrame
    edges_df = pd.DataFrame(list(G.edges(data=True)))
    edges_df.columns = ["Source", "Target", "Edge_Attrs"] 
    edges_df = conv_dict_cols(edges_df, "Edge_Attrs")    

    # save to csv --- for review
    csv_edge = graph_path.parent.joinpath(f"{graph_path.stem}_edge.csv")
    csv_node = graph_path.parent.joinpath(f"{graph_path.stem}_node.csv")
    nodes_df.to_csv(csv_node, index=False)
    edges_df.to_csv(csv_edge, index=False)
    
    # save to parquet --- for loading with remaining format
    parquet_edge = graph_path.parent.joinpath(f"{graph_path.stem}_edge.parquet")
    parquet_node = graph_path.parent.joinpath(f"{graph_path.stem}_node.parquet")
    nodes_df.to_parquet(parquet_edge, engine="pyarrow")
    edges_df.to_parquet(parquet_node, engine="pyarrow")

    return nodes_df, edges_df



if __name__ == "__main__":
    from pathlib import Path
    cur_path = Path.cwd()
    full_graph_ins = cur_path.parent.joinpath("data", "protograph", "full.graphml")
    conn_graph_ins = cur_path.parent.joinpath("data", "protograph", "conn.graphml")
    node_df, edge_df = graphml_csv(full_graph_ins)
    node_df, edge_df = graphml_csv(conn_graph_ins)