#[cfg(feature = "mold_tests")]
mod mold_tests;

#[allow(unused)]
fn should_not_ignore_tests(external_test: &str) -> bool {
    let wild_ignore_skip: Option<Vec<String>> =
        std::env::var("WILD_IGNORE_SKIP").ok().map(|test_suites| {
            test_suites
                .split(',')
                .map(|suite| suite.trim().to_string())
                .filter(|suite| !suite.is_empty())
                .collect()
        });

    wild_ignore_skip.is_some_and(|tests| {
        tests.contains(&external_test.to_string()) || tests.contains(&"all".to_string())
    })
}
