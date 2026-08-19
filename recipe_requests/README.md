# Recipe requests

`pending.csv` is the stable hand-off for requested libraries that do not yet have
an approved recipe.

- `source_discovery`: locate and corroborate a pinned source.
- `recipe_authoring`: a source is known and a declarative recipe can be drafted.

Filling candidate fields does not approve a recipe. The worker continues to resolve
builds only from the reviewed JSON files in `recipes/`.
