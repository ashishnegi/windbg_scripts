function log(x) {
    host.diagnostics.debugLog(x + "\n")
}
function exec(cmdstr) {
    return host.namespace.Debugger.Utility.Control.ExecuteCommand(cmdstr);
}
function all_rcws() {
    var obs = exec("!DumpHeap -short -type System.__ComObject")
    for (i of obs) {
        var cstr = "!do -nofields " + i
        foo = exec(cstr)
        for (j of foo) {
            if (j.includes("RCW") == true) {
                blah = exec("!DumpRCW " + j.substr(j.lastIndexOf(" ") + 1))
                for (k of blah) {
                    if (k.includes("IUnknown pointer") == true) {
                        log("ComObject: " + i + " " + j + " " + k)
                    }
                }
            }
        }
    }
}

function find_rcw(iuknown) {
    var obs = exec("!DumpHeap -short -type System.__ComObject")
    for (i of obs) {
        var cstr = "!do -nofields " + i
        foo = exec(cstr)
        for (j of foo) {
            if (j.includes("RCW") == true) {
                blah = exec("!DumpRCW " + j.substr(j.lastIndexOf(" ") + 1))
                for (k of blah) {
                    if ((k.includes("IUnknown pointer") == true) && k.includes(iuknown)) {
                        log("ComObject: " + i + " " + k)
                    }
                }
            }
        }
    }
}