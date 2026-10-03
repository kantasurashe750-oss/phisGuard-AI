import pytest
import pandas as pd

from backend.src.feature_extractor import LEXICAL_FEATURE_NAMES
from backend.src.train import _domain_split, _extract_dataset_features


def test_training_skips_invalid_urls_and_keeps_matching_labels():
    source = pd.DataFrame(
        {
            "url": [
                "good-one.example",
                "https://example.com:8443",
                "bad-one.example",
                "good-two.example",
                "bad-two.example",
                "good-three.example",
                "bad-three.example",
                "good-four.example",
                "bad-four.example",
                "good-five.example",
                "bad-five.example",
            ],
            "label": [0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1],
        }
    )

    features, labels, groups = _extract_dataset_features(source)

    assert len(features) == 10
    assert labels.tolist() == [0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
    assert len(groups) == 10
    assert list(features.columns) == LEXICAL_FEATURE_NAMES


def test_domain_split_keeps_test_domains_out_of_training():
    labels = pd.Series([0] * 50 + [1] * 50)
    groups = [
        f"legit{i}.example" for i in range(5) for _ in range(10)
    ] + [f"phish{i}.example" for i in range(5) for _ in range(10)]
    features = pd.DataFrame({"url_length": range(100)})

    train_indices, test_indices = _domain_split(features, labels, groups)

    assert set(groups[i] for i in train_indices).isdisjoint(
        set(groups[i] for i in test_indices)
    )
    assert labels.iloc[train_indices].nunique() == 2
    assert labels.iloc[test_indices].nunique() == 2
