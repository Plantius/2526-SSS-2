SELECT DISTINCT
    mc.code
FROM
    cve
    JOIN cwe_classification cc ON cc.cve_id = cve.cve_id
    JOIN cwe ON cwe.cwe_id = cc.cwe_id
    JOIN fixes f ON f.cve_id = cve.cve_id
    JOIN repository r ON r.repo_url = f.repo_url
    JOIN file_change fc ON fc.hash = f.hash
    JOIN method_change mc ON fc.file_change_id = mc.file_change_id
WHERE
    fc.programming_language = 'PHP'
    AND (
        LOWER(cwe.cwe_name) LIKE '%sql%'
        OR LOWER(cwe.description) LIKE '%sql%'
        OR LOWER(cwe.extended_description) LIKE '%sql%'
        OR LOWER(cve.description) LIKE '%sql%'
    )
    AND f.score >= 65
    AND mc.before_change = 'True'
    AND LOWER(cve.cve_id) LIKE 'cve-202%'