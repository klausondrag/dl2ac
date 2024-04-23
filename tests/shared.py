from hypothesis import strategies as st


rule_name_strategy = st.text(
    alphabet=st.characters(exclude_characters=['.', '\n']), min_size=1
)
