

from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
from newspaper.api import build
from newspaper import Config
from newspaper.source import Category, Source


CONFIG = Config()
CONFIG.memorize_articles = False
CONFIG.proxies = {'http': 'https://user-sp3dmjf4nd-country-fr:=O2G7cET0gfzz7gigr@isp.decodo.com:10000',
 'https': 'https://user-sp3dmjf4nd-country-fr:=O2G7cET0gfzz7gigr@isp.decodo.com:10000'}

def get_urls(url) :
    """
    Fetches the URLs from a given news source.

    Args:
        url (str): The URL of the news source.

    Returns:
       A list of URLs from the news source.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    paper = build(url, source_type="Company", config=CONFIG)
    return [article.url for article in paper.articles]


def get_newspaper4k_from_sources(sources: list, max_threads: int = 10):
    """
    Fetch URLs from a list of source websites using multithreading.

    This function utilizes ThreadPoolExecutor to perform parallel fetching of URLs from the provided
    list of source websites. It aggregates the results into a pandas DataFrame, including the source URL.

    Args:
        sources (list): List of base URLs to fetch data from.
        max_threads (int, optional): Maximum number of threads to use for parallel processing. Default is 10.

    Returns:
        pd.DataFrame: A DataFrame containing the fetched URLs, their source, and the source URL.
    """

    def fetch_urls(base_url):
        try:
            urls = get_urls(base_url)
            return [(url, base_url) for url in urls]
        except Exception as e:
            print(f"Error fetching from {base_url}: {e}")
            return []

    try:
        newspaper_data = []
        with ThreadPoolExecutor(max_threads) as executor:
            future_to_url = {executor.submit(fetch_urls, url): url for url in sources}

            for future in as_completed(future_to_url):
                url = future_to_url[future]

                result = future.result()
                if not result:
                    print(f"No data for URL - {url}")
                else:
                    newspaper_data.extend(result)

        # Create DataFrame with url and source_url columns
        df_newspaper = pd.DataFrame(newspaper_data, columns=["url", "source_url"])
        df_newspaper["api_source"] = "newspaper4k"

    except Exception as e:
        print("Error in get_newspaper4k_from_sources:", e)
        df_newspaper = pd.DataFrame(columns=["url", "source_url", "api_source"])

    return df_newspaper


if __name__ == "__main__":
    sources = [
        "https://www.bbc.com",
        "https://www.cnn.com",
        "https://www.aljazeera.com",
        "https://www.reuters.com",
        "https://www.nytimes.com"
    ]
    
    df_newspaper = get_newspaper4k_from_sources(sources, max_threads=5)
    # deduplicate URLs
    df_newspaper = df_newspaper.drop_duplicates(subset=["url"]).reset_index(drop=True)
    df2 = pd.read_excel("../news_monitoring/tmp/v1_mazars.xlsx")
    # deduplicate URLs in df2
    df2 = df2.drop_duplicates(subset=["url"]).reset_index(drop=True)
    df_merge = pd.merge(df_newspaper, df2, on="url", how="outer", indicator=True)
    # save df_merge to excel
    df_merge.to_excel("../news_monitoring/tmp/mazars/v_mazars.xlsx", index=False)
    # group by source_url
    df_gp = df_newspaper.groupby("source_url").size().reset_index(name="count")

    # get list of urls from soures not in df_newspaper
    urls_in_df = df_newspaper["source_url"].unique().tolist()
    urls_not_in_df = [url for url in sources if url not in urls_in_df]
    # add urls_not_in_df to df_gp with count 0
    not_in_gp = []
    for url in urls_not_in_df:
        not_in_gp.append({"source_url": url, "count": 0})
    df_gp = pd.concat([df_gp, pd.DataFrame(not_in_gp)], ignore_index=True)
    # sort by count
    df_gp = df_gp.sort_values(by="count", ascending=False)
    # save df_gp to excel
    df_gp.to_excel("../news_monitoring/tmp/mazars_stats.xlsx", index=False)
    print(df_newspaper.head())
    print(f"Total URLs fetched: {len(df_newspaper)}")   

