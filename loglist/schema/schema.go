package schema

type Log struct {
  Description string `json:"description"`
  Key string `json:"key"`
  MaximumMergeDelay float64 `json:"maximum_merge_delay"`
  Url string `json:"url"`
}

type LogList struct {
  Log []Log `json:"logs"`
}
