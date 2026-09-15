package com.example

import kotlinx.html.*

fun renderUser(input: String): String {
    val sb = StringBuilder()
    sb.append("<div>")
    unsafe { +input }
    sb.append("</div>")
    return sb.toString()
}

fun findUser(email: String, id: Int): User? {
    val q = "SELECT * FROM users WHERE email = '$email' AND id = $id"
    return db.query(q).firstOrNull()
}
