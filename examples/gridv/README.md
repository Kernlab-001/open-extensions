# GRIDV example

`initial-state.json` is the workbook state passed to
`open-extensions gridv init`: one sheet, one row and one column.

`cell-event.json` is a `cell.set` event that can be appended to the
workbook afterwards:

```bash
open-extensions gridv init demo --state gridv/initial-state.json -o book.gridv
open-extensions gridv append book.gridv --event gridv/cell-event.json
open-extensions gridv checkout book.gridv --seq 2
open-extensions gridv export book.gridv -o book.csv
```
