# Security notes

- 2026-11-05: Anonymous requester can read all recipes, including `is_public: false`, via `GET /recipes` -> server returns `200 OK` with full recipes list.
- 2026-11-06: Anonymous requester can modify an existing recipe via `PATCH /recipes/1` with JSON body `{"title": "Shakshuka (edited by anonymous)"}` -> server returns `200 OK` and response JSON shows the updated title.
- 2026-11-06: Anonymous requester can delete an existing recipe via `DELETE /recipes/1` -> server returns `204 NO CONTENT`, and a following `GET /recipes` shows that recipe `id: 1` is missing from the list.

