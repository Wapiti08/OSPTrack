'''
 # @ Create Time: 2024-08-19 15:35:02
 # @ Modified time: 2024-08-19 15:35:06
 # @ Description: Auxiliary functions
 '''
from datetime import datetime


def ts_format(timestamp):
    ''' convert format timestamp to numeric number 
    
    '''
    format_str = f"%Y-%m-%d %H:%M:%S"
    corr_ts = timestamp[:19]
    # parse the timestamp into a datetime object
    dt = datetime.strptime(corr_ts, format_str)

    return dt.timestamp()


if __name__ == "__main__":
    timestamp = "2018-10-25 20:44:04.936925952"
    print(ts_format(timestamp))




