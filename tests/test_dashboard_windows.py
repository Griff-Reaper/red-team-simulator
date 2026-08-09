"""Tests for the dashboard time-window tabs (filter + empty-state rendering)."""

from datetime import datetime, timezone

from generate_dashboard import (
    filter_results_for_window,
    generate_html,
    compute_stats,
    DASHBOARD_WINDOWS,
)

NOW = datetime(2026, 8, 9, 12, 0, 0, tzinfo=timezone.utc)


def _r(ts):
    return {
        "technique_id": "PI-001", "technique_name": "n", "category": "prompt_injection",
        "severity": "high", "target": "bedrock", "success": False, "impact_score": 0,
        "timestamp": ts, "response": "I cannot help.", "notes": "",
    }


RESULTS = [
    _r("2026-08-09T09:00:00+00:00"),  # today
    _r("2026-08-08T09:00:00+00:00"),  # yesterday
    _r("2026-08-04T09:00:00+00:00"),  # 5 days ago
    _r("2026-07-20T09:00:00+00:00"),  # 20 days ago
    _r("2026-06-10T09:00:00+00:00"),  # 60 days ago
    _r(""),                            # unparseable timestamp
]


def test_all_window_includes_everything_even_bad_timestamps():
    out = filter_results_for_window(RESULTS, "all", NOW)
    assert len(out) == len(RESULTS)  # nothing dropped from the complete report


def test_latest_window_is_the_most_recent_day():
    out = filter_results_for_window(RESULTS, "latest", NOW)
    # Only 2026-08-09 records; bad-timestamp row excluded.
    assert len(out) == 1
    assert out[0]["timestamp"].startswith("2026-08-09")


def test_7d_window_is_rolling():
    out = filter_results_for_window(RESULTS, "7d", NOW)
    # today, yesterday, 5-days-ago (>= 2026-08-02); 20d/60d/bad excluded.
    assert len(out) == 3


def test_30d_window_is_rolling():
    out = filter_results_for_window(RESULTS, "30d", NOW)
    # adds the 20-days-ago record; 60d and bad excluded.
    assert len(out) == 4


def test_windows_are_nested_subsets():
    counts = {w: len(filter_results_for_window(RESULTS, w, NOW))
              for w in ("latest", "7d", "30d", "all")}
    assert counts["latest"] <= counts["7d"] <= counts["30d"] <= counts["all"]


def test_empty_window_renders_no_data_not_a_perfect_score():
    # A rolling window as-of a far-future date has no records (unlike "latest",
    # which always resolves to the most recent day present in the data).
    empty = filter_results_for_window(RESULTS, "7d", datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert empty == []
    html = generate_html(compute_stats(empty), empty, active_window="7d",
                         window_counts={"latest": 1, "7d": 0, "30d": 0, "all": 6})
    assert "NO ATTACKS IN THIS WINDOW" in html
    assert "SECURITY POSTURE" not in html  # no misleading A+ scorecard
    assert "Successful Hits" not in html


def test_tabs_render_with_active_and_counts():
    results = filter_results_for_window(RESULTS, "all", NOW)
    counts = {"latest": 1, "7d": 3, "30d": 4, "all": 6}
    html = generate_html(compute_stats(results), results, active_window="all",
                         window_counts=counts)
    assert 'class="window-tabs' in html
    # active window highlighted, every window linked
    assert 'window-tab active" href="index.html"' in html
    for w in DASHBOARD_WINDOWS:
        assert f'href="{w["file"]}"' in html


def test_tabs_hidden_when_counts_absent():
    # Legacy / single-file generation passes no counts → no tab bar.
    results = filter_results_for_window(RESULTS, "all", NOW)
    html = generate_html(compute_stats(results), results)
    assert 'class="window-tabs' not in html
