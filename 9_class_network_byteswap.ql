import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
    exists(MacroInvocation i|
      // TODO: <condition>
      i.getMacroName().regexpMatch("ntoh.*") and i.getExpr() = this
    )
  } 
}

from NetworkByteSwap n
select n, "Network byte swap" 