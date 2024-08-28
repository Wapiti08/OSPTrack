'''
 # @ Create Time: 2024-08-27 15:57:03
 # @ Modified time: 2024-08-27 16:04:56
 # @ Description:

the organization of analysis in package-analysis:

    install: {
        Status: string
        Stdout: string
        Stderr: string
        DNS: [
            {
            Class: string
            Queries: [
                {
                Hostname: string
                Types: [string]
                }
            ]
        }
        ] 
  Commands: [
    {
      Command: [string]
      Environment: [string]
    }
  ]
  Sockets: [
    {
      Hostnames: [string]
      Port: integer
      Address: string
    }
  ]
  Files: [
    {
      Delete: boolean
      Write: boolean
      Read: boolean
      Path: string
    }
  ]
}


 '''

import pandas as pd
import json
from pathlib import Path
import re
import base64
import numpy as np

# Custom encoder to handle numpy arrays
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)


# Custom encoder to handle bytes
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return super(BytesEncoder, self).default(obj)

class CombinedEncoder(BytesEncoder, NumpyEncoder):
    def default(self, obj):
        # BytesEncoder will be checked first, then NdarrayEncoder
        return super(CombinedEncoder, self).default(obj)

class Featurer:
    def __init__(self,):
        # Define regex patterns
        self.patterns = {
            "install":{
                "Status": r'"Status":\s*"([^"]*)"',
                "Stdout": r'\s*b"([^"]*)"',
                "Stderr": r'"Stderr":\s*"([^"]*)"',
            },
            "DNS": {
                "Class": r'"Class":\s*"([^"]*)"',
                "Queries": {
                    "Hostname": r'"Hostname":\s*"([^"]*)"',
                    "Types": r'"Types":\s*array\(\[([^\]]*)\],\s*dtype=object\)'
                }
            },
            "Commands": {
                "EntireStructure": r"""
                    \{'Command':\s*(array\(\[.*?\],\s*dtype=object\)),  # Match the Command array
                    \s*'Environment':\s*(array\(\[.*?\],\s*dtype=object\))  # Match the Environment array
                    \}
                """
            },
            "Sockets": {
                "Hostnames": r'\s*array\(\[([^\]]*)\],\s*dtype=object\)',
                "Port": r'"Port":\s*(\d+)',
                "Address": r'"Address":\s*"([^"]*)"',
            },
            "Files": {
                "Delete": r'"Delete":\s*(true|false)',
                "Write": r'"Write":\s*(true|false)',
                "Read": r'"Read":\s*(true|false)',
                "Path": r'"Path":\s*"([^"]*)"'
            }
        }


    # Extract data
    def extract_data(self, patterns, text):
        
        if isinstance(text, str):
            self.string_match(patterns, text)

        elif isinstance(text, dict):
            print(json.dumps(text, indent=1, cls=CombinedEncoder))

    
    def string_match(self, patterns, text):
        result = {}
        # replace the ' to " in text
        text = text.replace("'", '"')
        for key, pattern in patterns.items():
            if isinstance(pattern, dict):
                result[key] = self.extract_data(pattern, text)
            else:
                if key == "EntireStructure":
                    # re.DOTALL makes '.' in the regex match newline characters, allowing the pattern to match multiple lines
                    # re.VERBOSE allows the use of whitespace and comments inside the regex pattern
                    match = re.findall(pattern, text, re.DOTALL | re.VERBOSE)
                else:
                    match = re.findall(pattern, text)

                if match:
                    if key == "EntireStructure":
                        result[key] = [self.parse_command_env(m) for m in match]
                    else:
                        result[key] = match[0] if len(match) == 1 else match
        return result

    
    def cmd_concat(self, match: re.Match):
        ''' concat commands to one string
        
        '''
        command_str, env_str = match
        command_list = [item.strip().strip("'") for item in command_str.split(',')]
        env_list = [item.strip().strip("'") for item in env_str.split(',')]
        return {"Command": command_list, "Environment": env_list}


if __name__ == "__main__":
    # define the pkg_folder
    pkg_folder = Path.cwd().parent.joinpath("data","package-analysis.parquet")
    df = pd.read_parquet(pkg_folder)
    json_example = df["Analysis"][0]
    featurer_ext = Featurer()
    data = featurer_ext.extract_data(featurer_ext.patterns, json_example)
    print(data)
