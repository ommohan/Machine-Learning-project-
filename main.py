import pandas as pd

data = pd.read_csv(r"C:\\Users\\Om Mohan\\OneDrive\\Desktop\\project\\malicious_phish.csv")
print(data)
df = pd.DataFrame(data)

def fetures_extract(df):
    df['url_legnth'] = df['url'].apply(len)
    df['domain'] = df['url'].apply(lambda x: x.split('/')[0])
    df['Has https'] = df['url'].apply(lambda x: int('https' in x))
    df['num_dots'] = df['url'].apply(lambda x: x.count('.'))
    df['has_symbol'] = df['url'].apply(lambda x: int('@' in x))
    df['has_ip'] = df['url'].apply(lambda x: int(any(char.isdigit()for char in x.split('/')[0])))
    df['num_slashes'] = df['url'].apply(lambda x: x.count('/'))
   
    
    return df

    


data_extract = fetures_extract(df)
print(data_extract)
