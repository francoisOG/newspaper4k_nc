import re
import lxml
from newspaper.source import Category, Source
import tldextract
from typing import Any, Dict, Iterator, List, Optional, Tuple
from newspaper import urls
from newspaper.configuration import Configuration
from newspaper.extractors.defines import url_stopwords, category_url_prefixes
import newspaper.parsers as parsers
from newspaper import Config


def _get_other_links(
    doc: lxml.html.Element, filter_tld: Optional[str] = None
) -> Iterator[str]:
    """Return all links that are not as <a> tags. These can be
    links in javascript tags, json objects, etc.
    """
    html = parsers.node_to_string(doc)
    candidates = re.findall(r'"(https?:\\?/\\?/[^"]*)"', html)

    candidates = [c.replace(r"\/", "/") for c in candidates]
    candidates = [c.replace(r"/\\", "/") for c in candidates]

    def _filter(candidate):
        if filter_tld is not None:
            candidate_tld = tldextract.extract(candidate)
            if candidate_tld.domain != filter_tld:
                return False
        if re.search(r"\.(css|js|json|xml|rss|jpg|jpeg|png|)$", candidate, re.I):
            return False

        path = urls.get_path(candidate, allow_fragments=False)
        path_chunks = [x for x in path.split("/") if len(x) > 0]
        if "index.html" in path_chunks:
            path_chunks.remove("index.html")

        if len(path_chunks) > 2 or len(path_chunks) == 0:
            return False

        return True

    return filter(_filter, candidates)


def is_valid_link(url: str, filter_tld: str) -> Tuple[bool, Dict[str, Any]]:
    """Is the url a possible category?"""
    parsed_url: Dict[str, Any] = {
        "scheme": urls.get_scheme(url, allow_fragments=False),
        "domain": urls.get_domain(url, allow_fragments=False),
        "path": urls.get_path(url, allow_fragments=False),
        "tld": None,
    }

    # No domain or path
    if not parsed_url["domain"] or not parsed_url["path"]:
        return False, parsed_url
    # remove any url that starts with #
    if parsed_url["path"] and parsed_url["path"].startswith("#"):
        return False, parsed_url
    # remove urls that are not http or https (ex. mailto:)
    if parsed_url["scheme"] and (
        parsed_url["scheme"] != "http" and parsed_url["scheme"] != "https"
    ):
        return False, parsed_url

    path_chunks = [x for x in parsed_url["path"].split("/") if len(x) > 0]
    if "index.html" in path_chunks:
        path_chunks.remove("index.html")

    if parsed_url["domain"]:
        child_tld = tldextract.extract(url)
        parsed_url["tld"] = child_tld
        child_subdomain_parts = child_tld.subdomain.split(".")

        # Ex. microsoft.com is definitely not related to
        # espn.com, but espn.go.com is probably related to espn.com
        if child_tld.domain != filter_tld and filter_tld not in child_subdomain_parts:
            return False, parsed_url

        if child_tld.subdomain in ["m", "i"]:
            return False, parsed_url

        subd = "" if child_tld.subdomain == "www" else child_tld.subdomain

        if len(subd) > 0 and len(path_chunks) == 0:
            return True, parsed_url  # Allow http://category.domain.tld/

    # we want a path with just one subdir
    # cnn.com/world and cnn.com/world/ are both valid_categories
    # cnn.com/world/europe is not a valid_category
    # europe.cnn.com/economy is a valid_category
    if len(path_chunks) > 2 or len(path_chunks) == 0:
        return False, parsed_url

    if any(
        [x.startswith("_") or x.startswith("#") for x in path_chunks]
    ):  # Ex. cnn.com/_static/
        return False, parsed_url

    if len(path_chunks) == 2 and path_chunks[0] in category_url_prefixes:
        return True, parsed_url

    return len(path_chunks) == 1 and 1 < len(path_chunks[0]) < 20, parsed_url


def is_valid_link_v2(url: str, filter_tld: str) -> Tuple[bool, Dict[str, Any]]:
    """
    Optimized function to determine if a URL represents a valid category page.

    Args:
        url: The URL to validate
        filter_tld: The target domain to filter for

    Returns:
        Tuple of (is_valid: bool, parsed_url_info: dict)
    """

    # Common locale patterns (language/country codes)
    locale_pattern = re.compile(r"^[a-z]{2}(_[a-z]{2})?$", re.IGNORECASE)

    # Words that typically indicate non-category pages
    non_category_indicators = {
        "sitemap",
        "search",
        "login",
        "logout",
        "register",
        "signup",
        "signin",
        "admin",
        "api",
        "rss",
        "feed",
        "xml",
        "json",
        "pdf",
        "download",
        "print",
        "share",
        "edit",
        "delete",
        "create",
        "new",
        "add",
        "update",
        "forms",
        "form",
        "submit",
        "confirmation",
        "thank-you",
        "error",
        "404",
        "500",
        "maintenance",
        "coming-soon",
    }

    parsed_url: Dict[str, Any] = {
        "scheme": (
            urls.get_scheme(url, allow_fragments=False) if "urls" in globals() else None
        ),
        "domain": (
            urls.get_domain(url, allow_fragments=False) if "urls" in globals() else None
        ),
        "path": (
            urls.get_path(url, allow_fragments=False) if "urls" in globals() else url
        ),
        "tld": None,
        "is_category": False,
        "category_type": None,
        "locale": None,
    }

    # Handle case where urls module is not available - extract from URL directly
    if "urls" not in globals():
        if url.startswith(("http://", "https://")):
            parts = url.split("/", 3)
            parsed_url["scheme"] = parts[0][:-1]  # Remove the colon
            parsed_url["domain"] = parts[2] if len(parts) > 2 else None
            parsed_url["path"] = "/" + parts[3] if len(parts) > 3 else "/"
        else:
            parsed_url["path"] = url if url else "/"

    path = parsed_url["path"] or ""

    # Basic validation - must have a path
    if not path or path == "/":
        return False, parsed_url

    # Remove fragment identifiers and reject if starts with fragment
    if path.startswith("#"):
        return False, parsed_url

    # Handle scheme validation if available
    if parsed_url["scheme"] and parsed_url["scheme"] not in ("http", "https"):
        return False, parsed_url

    # Parse path segments
    path_chunks = [x for x in path.split("/") if len(x) > 0]

    # Remove common non-content files
    if "index.html" in path_chunks:
        path_chunks.remove("index.html")

    if not path_chunks:
        return False, parsed_url

    # Domain validation if filter_tld is provided and domain is available
    if filter_tld and parsed_url["domain"]:
        try:
            child_tld = tldextract.extract(url)
            parsed_url["tld"] = child_tld
            child_subdomain_parts = child_tld.subdomain.split(".")

            # Check domain relationship
            if (
                child_tld.domain != filter_tld
                and filter_tld not in child_subdomain_parts
            ):
                return False, parsed_url

            # Reject mobile/international subdomains that aren't category-focused
            if child_tld.subdomain in ["m", "i", "mobile"]:
                return False, parsed_url
        except:
            # If tldextract fails, continue with path validation
            pass

    # Reject paths with private/system indicators
    if any(chunk.startswith(("_", "#", ".")) for chunk in path_chunks):
        return False, parsed_url

    # Check for non-category indicators
    if any(
        indicator in chunk.lower()
        for chunk in path_chunks
        for indicator in non_category_indicators
    ):
        return False, parsed_url

    # Analyze path structure
    num_chunks = len(path_chunks)

    # Single segment path - check if it's a reasonable category name
    if num_chunks == 1:
        segment = path_chunks[0].lower()
        # Must be reasonable length and potentially a category
        if 2 <= len(segment) <= 30 and (
            segment in category_url_prefixes
            or not any(char.isdigit() for char in segment)  # Avoid article IDs
        ):
            parsed_url["is_category"] = True
            parsed_url["category_type"] = "root_category"
            return True, parsed_url

    # Two segment path - common pattern for localized sites
    elif num_chunks == 2:
        first_segment = path_chunks[0].lower()
        second_segment = path_chunks[1].lower()

        # Check if first segment is a locale (e.g., 'fr_fr', 'en_us')
        if locale_pattern.match(first_segment):
            parsed_url["locale"] = first_segment
            # Second segment should be a category
            if second_segment in category_url_prefixes or (
                2 <= len(second_segment) <= 30
                and not any(char.isdigit() for char in second_segment)
            ):
                parsed_url["is_category"] = True
                parsed_url["category_type"] = "localized_category"
                return True, parsed_url

        # Or first segment is a known category prefix
        elif first_segment in category_url_prefixes:
            parsed_url["is_category"] = True
            parsed_url["category_type"] = "subcategory"
            return True, parsed_url

    # Three segment path - locale + category + subcategory
    elif num_chunks == 3:
        first_segment = path_chunks[0].lower()
        second_segment = path_chunks[1].lower()
        third_segment = path_chunks[2].lower()

        # Locale + category + subcategory pattern
        if (
            locale_pattern.match(first_segment)
            and second_segment in category_url_prefixes
            and 2 <= len(third_segment) <= 30
            and not any(char.isdigit() for char in third_segment)
        ):
            parsed_url["locale"] = first_segment
            parsed_url["is_category"] = True
            parsed_url["category_type"] = "localized_subcategory"
            return True, parsed_url

    # Four or more segments - likely too deep to be a main category
    # But allow some exceptions for well-structured category hierarchies
    elif num_chunks == 4:
        first_segment = path_chunks[0].lower()
        second_segment = path_chunks[1].lower()

        # Very specific case: locale + category + subcategory + sub-subcategory
        if (
            locale_pattern.match(first_segment)
            and second_segment in category_url_prefixes
            and all(
                2 <= len(chunk) <= 20 and not chunk.isdigit()
                for chunk in path_chunks[2:]
            )
        ):
            parsed_url["locale"] = first_segment
            parsed_url["is_category"] = True
            parsed_url["category_type"] = "deep_category"
            return True, parsed_url

    return False, parsed_url


def category_parser(source_url: str, doc: lxml.html.Element) -> List[str]:
    """Inputs source lxml root and source url, extracts domain and
    finds all of the top level urls, we are assuming that these are
    the category urls.
    cnn.com --> [cnn.com/latest, world.cnn.com, cnn.com/asia]
    """
    domain_tld = tldextract.extract(source_url)

    links_in_doc = set([a.get("href") for a in parsers.get_tags(doc, tag="a")])

    category_candidates: List[Any] = []

    for p_url in links_in_doc:
        ok, parsed_url = is_valid_link_v2(p_url, domain_tld.domain)
        if ok:
            if not parsed_url["domain"]:
                parsed_url["domain"] = urls.get_domain(
                    source_url, allow_fragments=False
                )
                parsed_url["scheme"] = urls.get_scheme(
                    source_url, allow_fragments=False
                )
                parsed_url["tld"] = domain_tld

            category_candidates.append(parsed_url)

    _valid_categories = []

    stop_words = set(url_stopwords)
    for p_url in category_candidates:
        path = p_url["path"].lower().split("/")
        subdomain = p_url["tld"].subdomain.lower().split(".")

        conjunction = set(path + subdomain)
        if len(conjunction.intersection(stop_words)) == 0:
            p_url["scheme"] = p_url["scheme"] if p_url["scheme"] else "http"
            if p_url["path"].endswith("/"):
                p_url["path"] = p_url["path"][:-1]
            _valid_categories.append(
                p_url["scheme"] + "://" + p_url["domain"] + p_url["path"]
            )

    if len(_valid_categories) == 0:
        other_links_in_doc = set(_get_other_links(doc, filter_tld=domain_tld.domain))
        for p_url in other_links_in_doc:
            ok, parsed_url = is_valid_link_v2(p_url, domain_tld.domain)
            if ok:
                path = parsed_url["path"].lower().split("/")
                subdomain = parsed_url["tld"].subdomain.lower().split(".")
                conjunction = set(path + subdomain)

                if len(conjunction.intersection(stop_words)) == 0:
                    _valid_categories.append(
                        parsed_url["scheme"]
                        + "://"
                        + parsed_url["domain"]
                        + parsed_url["path"]
                    )

    _valid_categories.append("/")  # add the root

    _valid_categories = list(set(_valid_categories))

    category_urls = [
        urls.prepare_url(p_url, source_url)
        for p_url in _valid_categories
        if p_url is not None
    ]

    categories = sorted(category_urls)
    return categories


if __name__ == "__main__":

    CONFIG = Config()
    CONFIG.memorize_articles = False
    CONFIG.proxies = {
        "http": "https://user-sp3dmjf4nd-country-fr:=O2G7cET0gfzz7gigr@isp.decodo.com:10000",
        "https": "https://user-sp3dmjf4nd-country-fr:=O2G7cET0gfzz7gigr@isp.decodo.com:10000",
    }

    url = "https://www.ey.com"
    source_type = "Company"
    s = Source(url, config=CONFIG, source_type=source_type)

    input_html = only_homepage = only_in_path = False
    s.download()
    s.parse()

    if only_homepage:
        # The only category we will parse is Homepage
        s.categories = [Category(url=s.url, html=s.html, doc=s.doc)]
    else:
        url_list = category_parser(s.url, s.doc)
        s.categories = [Category(url=url) for url in set(url_list)]
        # s.set_categories()
        s.download_categories()  # mthread
    s.parse_categories()

    if not only_homepage:
        s.set_feeds()
        s.download_feeds()  # mthread
    # s.parse_feeds()

    s.generate_articles(only_in_path=only_in_path)

    # links = ['https://www.youtube.com/EYFranceOfficiel']

    # l2 = list(links_in_doc)
    # # get all links not in links_in_doc
    # l3 = [l for l in l2 if l not in links]
    # tag="a"
    # selector = f".//{(tag or '*')}"
    # elems = doc.xpath(selector)
    # links_in_doc = set([a.get("href") for a in elems])
    # valid =[]
    # for p_url in links_in_doc:
    #     ok, parsed_url = is_valid_link(p_url, domain_tld.domain)
    #     valid.append({'ok': ok, 'parsed_url': p_url})
    # df_valid = pd.DataFrame(valid)
