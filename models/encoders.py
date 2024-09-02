'''
 # @ Create Time: 2024-08-20 13:41:54
 # @ Modified time: 2024-08-20 13:41:56
 # @ Description: define diverse encoders for node/edge attributes
 '''
from sentence_transformers import SentenceTransformer
import torch


class SequenceEncoder:
    ''' cover sequence encoding for path, domain, cmd, user, process, event
    
    '''
    def __init__(self, model_name='all-MiniLM-L6-v2', device=None):
        self.model = SentenceTransformer(model_name, device=device)
        self.device = device

    @torch.no_grad()
    def __call__(self, df):
        x = self.model.encode(df.values, show_progress_bar=True,
                              convert_to_tensor=True, device=self.device)

        return x.cpu()


class IdentityEncoder:
    ''' cover numeric encoding for ports, or other numeric value/attributes
    
    '''
    def __init__(self, dtype=None):
        self.dtype = dtype
    
    def __call__(self, df):
        return torch.from_numpy(df.values).view(-1,1).to(self.dtype)



class CateEncoder:
    ''' cover categorical encoding for status, response code
    
    status: limited choices - one-hot encoding
    
    '''
    def __init__(self,):
        self.mapping = None
    
    def __call__(self, df):
        ''' Encodes the specified column in the DataFrame using one-hot encoding
        
        '''
        if self.mapping is None:
            # create a mapping if it doesn't exist
            # get all the types
            types = df.values.unique().tolist()
            # create mapping
            mapping = {type: i for i, type in enumerate(types)}

        # create a tensor of zeros
        x = torch.zeros(len(df), len(self.mapping))

        for i, value in enumerate(df[self.column]):
            x[i, self.mapping[value]] = 1
        
        return x

    def update(self, df):
        ''' update the mapping based on new data in the DataFrame
        
        '''
        if self.mapping is None:
            self.__call__(df)
        
        else:
            new_types = df.values.unique().tolist()
            for type_ in new_types:
                if type_ not in self.mapping:
                    self.mapping[type_] = len(self.mapping)
        





