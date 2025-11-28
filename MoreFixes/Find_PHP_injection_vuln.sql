SELECT DISTINCT (fc.file_change_id),
    fc.code_before AS php_other_injection_count
FROM
    cve
    JOIN cwe_classification cc ON cc.cve_id = cve.cve_id
    JOIN cwe ON cwe.cwe_id = cc.cwe_id
    JOIN fixes f ON f.cve_id = cve.cve_id
    JOIN repository r ON r.repo_url = f.repo_url
    JOIN file_change fc ON fc.hash = f.hash
WHERE
    fc.programming_language = 'PHP'
    AND (
        LOWER(cwe.cwe_name) LIKE '%injection%'
        OR LOWER(cwe.description) LIKE '%injection%'
        OR LOWER(cwe.extended_description) LIKE '%injection%'
        OR LOWER(cve.description) LIKE '%injection%'
    )
    AND f.score >= 65
    AND LOWER(cve.cve_id) LIKE 'cve-2024-%';