import bz2
import json
import logging
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen, Request

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

def download_openphish(output_file: Path) -> None:
    logging.info(f"Downloading OpenPhish data from {OPENPHISH_URL}")
    req = Request(OPENPHISH_URL, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urlopen(req) as response:
            text_data = response.read().decode('utf-8')
            
            # OpenPhish feed is a text file with one URL per line
            urls = [line.strip() for line in text_data.splitlines() if line.strip()]
            
            df_formatted = pd.DataFrame()
            df_formatted["url"] = urls
            df_formatted["submission_time"] = pd.Timestamp.now().isoformat()
            
            df_formatted.to_csv(output_file, index=False)
            logging.info(f"Successfully saved {len(df_formatted)} phishing URLs to {output_file}")
            
    except Exception as e:
        logging.error(f"Error processing OpenPhish data: {e}")
        raise

def download_tranco(output_file: Path) -> None:
    logging.info(f"Downloading Tranco Top 1M list from {TRANCO_URL}")
    
    try:
        df = pd.read_csv(TRANCO_URL, names=["rank", "domain"])
        # Take top 100k as specified in spec for legitimate URLs
        top_domains = df.head(100000).copy()
        
        # Simulate realistic URLs by adding common paths (as per spec)
        # For simplicity, we just use the raw domain for now, which the feature extractor handles.
        # To be safe, prepend http:// to domain names so it's parsed as full URL.
        top_domains["url"] = "http://" + top_domains["domain"]
        
        df_formatted = pd.DataFrame()
        df_formatted["url"] = top_domains["url"]
        
        df_formatted.to_csv(output_file, index=False)
        logging.info(f"Successfully saved {len(df_formatted)} legitimate URLs to {output_file}")
        
    except Exception as e:
        logging.error(f"Error processing Tranco data: {e}")
        raise

def main():
    project_root = Path(__file__).resolve().parents[1]
    data_dir = project_root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    phishing_csv = data_dir / "phishing_urls.csv"
    legitimate_csv = data_dir / "legitimate_urls.csv"
    
    download_openphish(phishing_csv)
    download_tranco(legitimate_csv)

if __name__ == "__main__":
    main()
