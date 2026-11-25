Summarize this GitHub Actions failure in up to three short bullets. Identify the first
failed step, the relevant checks that passed, and whether retrying the same inputs is
likely to help. Interpret `candidate_failure`: `strict_pattern` means the deterministic
locator stopped on a changed semantic pattern; `llm_recipe_rejected` means an opencode
proposal was rejected by the strict validator; `llm_no_proposal` means opencode produced
no usable proposal; `other` or null means a pattern failure is unconfirmed. Report CI
findings only. Do not propose code changes, validation changes, or ways to alter the
upstream binary.
