'''
 # @ Create Time: 2024-08-20 13:41:54
 # @ Modified time: 2024-08-20 13:41:56
 # @ Description: define diverse encoders for node/edge attributes
 '''
from sentence_transformers import SentenceTransformer
import torch


class SequenceEncoder:
    ''' cover sequence encoding for path, domain
    
    '''
    def __init__(self, model_name='all-MiniLM-L6-v2', device=None):
        self.model = SentenceTransformer(model_name, device=device)
        self.device = device

    @torch.no_grad()
    def __call__(self, df):
        x = self.model.encode(df.values, show_progress_bar=True,
                              convert_to_tensor=True, device=self.device)

        return x.cpu()


class NumEncoder:
    ''' cover numeric encoding for ports, or other numeric value/attributes
    
    '''
    def __init__():
        
    
    def __call__():




class CateEncoder:
    ''' cover categorical encoding for status, user, process, event, ip
    
    '''
    def __init__(self, ):
        pass
    
    def __call__(self, df):
        ''' 
        
        '''
    
    def update(self, df):
        





