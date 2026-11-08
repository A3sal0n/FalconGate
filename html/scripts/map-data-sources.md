# Map files

The traffic map on the Network Statistics page uses these local files. Nothing is fetched from an external service.

| File | Source | License |
|---|---|---|
| `chartjs-chart-geo-4.3.6.umd.min.js` | npm package `chartjs-chart-geo` 4.3.6, `build/index.umd.min.js`, unmodified | MIT, see `chartjs-chart-geo-LICENSE.md` |
| `countries-110m.json` | npm package `world-atlas` 2.0.2, unmodified | ISC, see `world-atlas-LICENSE.md`. The geometry comes from Natural Earth, which is public domain. |
| `country_points.json` | Generated from Natural Earth's `ne_10m_admin_0_countries` and `ne_10m_admin_0_map_units` | Public domain |

`country_points.json` maps each ISO country code to `[name, latitude, longitude]`, using Natural Earth's label point for the position. Antarctica and `UM` (U.S. Minor Outlying Islands) are not included.
