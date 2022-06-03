/**
* @name Missing token verification
* @description Missing token verification
* @id go/jwt-sign-check
* @kind problem
* @problem.severity warning
* @precision high
* @tags security
*/
import go
/*
* Identify processors that are missing the token verification:
*
* func(token *jwt.Token) (interface{}, error) {
*    // Don't forget to validate the alg is what you expect:
*    //if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
*    //        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
*    //}
*    ...
* }
*/
from FuncLit f
where
    // Identify the function via the argument part of the its signature
    //     func(token *jwt.Token) (interface{}, error) { ... }
    f.getParameter(0).getType() instanceof PointerType and
    f.getParameter(0).getType().(PointerType).getBaseType().getName() = "Token" and
    f.getParameter(0).getType().(PointerType).getBaseType().getPackage().getName() = "jwt" and
    // and check whether it uses jwt.SigningMethodHMAC in any way
    not exists(TypeExpr t |
        f.getBody().getAChild*() = t and
        t.getType().getName() = "SigningMethodHMAC" and
        t.getType().getPackage().getName() = "jwt"
    )
select f, "This function should be using jwt.SigningMethodHMAC"
