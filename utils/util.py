'''
 # @ Create Time: 2024-08-19 15:35:02
 # @ Modified time: 2024-08-19 15:35:06
 # @ Description: Auxiliary functions
 '''
from datetime import datetime


def ts_format(timestamp):
    ''' convert format timestamp to numeric number 
    
    '''
    format_str = "%Y-%b-%d %H:%M:%S.%f"

    # parse the timestamp into a datetime object
    dt = datetime.strptime(timestamp, format_str)

    return dt.timestamp()