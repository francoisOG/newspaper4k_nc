import re
from typing import Optional
import lxml

from newspaper.configuration import Configuration
from newspaper.languages import language_regex
import newspaper.parsers as parsers
from newspaper.extractors.defines import (
    MOTLEY_REPLACEMENT,
    TITLE_META_INFO,
    TITLE_REPLACEMENTS,
)


class TitleExtractor:
    def __init__(self, config: Configuration) -> None:
        self.config = config
        self.title: str = ""

    def parse(self, doc: lxml.html.Element) -> str:
        """Fetch the article title and analyze it

        Assumptions:
        - title tag is the most reliable (inherited from Goose)
        - h1, if properly detected, is the best (visible to users)
        - og:title and h1 can help improve the title extraction
        - python == is too strict, often we need to compare filtered
          versions, i.e. lowercase and ignoring special chars

        Explicit rules:
        1. title == h1, no need to split
        2. h1 similar to og:title, use h1
        3. title contains h1, title contains og:title, len(h1) > len(og:title), use h1
        4. title starts with og:title, use og:title
        5. use title, after splitting
        """
        self.title = ""
        title_element = parsers.get_tags(doc, tag="title")
        # no title found
        if title_element is None or len(title_element) == 0:
            return self.title

        # title elem found
        title_text = parsers.get_text(title_element[0])
        self.title = title_text.strip()
        return self.title

    def _split_title(self, title: str, delimiter: str, hint: Optional[str] = None):
        """Split the title to best part possible"""
        large_text_length = 0
        large_text_index = 0
        title_pieces = title.split(delimiter)

        if hint:
            filter_regex = re.compile(r"[^a-zA-Z0-9\ ]")
            hint = filter_regex.sub("", hint).lower()

        # find the largest title piece
        for i, title_piece in enumerate(title_pieces):
            current = title_piece.strip()
            if hint and hint in filter_regex.sub("", current).lower():
                large_text_index = i
                break
            if len(current) > large_text_length:
                large_text_length = len(current)
                large_text_index = i

        # replace content
        title = title_pieces[large_text_index]
        return title.replace(*TITLE_REPLACEMENTS)
