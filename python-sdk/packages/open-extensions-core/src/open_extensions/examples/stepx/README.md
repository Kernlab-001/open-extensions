# STEPX example

`pancakes.json` is a valid STEPX 0.1.0 document: a recipe with four
ingredients, two steps, a timer, a prerequisite, and a conditional
substitution.

Try it:

```bash
open-extensions stepx create stepx/pancakes.json recipe.stepx
open-extensions stepx scale recipe.stepx --yield 10 --output recipe-10.stepx
open-extensions stepx render recipe.stepx --format markdown
```
