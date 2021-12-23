// Groups all coroutine frames for a coroutine function into unique stack walks.
// This helps in finding what all coroutines are present in process/dump.
// This is a best effort system. The output will mostly be good but can have some noise as
// we don't know when to stop walking up the coroutine parent frames.
// parameters:
// coro_fn_address  : (String) Address of coroutine function for which you want to find all stack frames.
//                    You can get this value from output of `x FabricRuntime!*TStore*TryGetValueAsync*_ResumeCoro$2`.
//                    This needs to be hex address.
// first_n          : (Int) Look at first n heaps containing coro_fn_address.
// call_stack_depth : (Int) Depth to go down in call stack. Start from low numbers like `3`.
// dll_base_start   : (Long) start address of functions above which only we consider coroutine walk to continue.
// dll_base_end     : (Long) end address of functions under which we consider coroutine walk to continue.
//                    You can get dll_base_start/end from e.g. `lmDf m FabricRuntime`
// example usage:
//> dx @$scriptContents.unique_coroutine_frames("00007ff62318bf80", 600, 3, 0x00007ff621310000, 0x00007ff624210000)
// Printing Map.
// Map size: 1
//,0x7ff62210b9f0,0x7ff623035ee0,00007ff62318bf80 => 512
//> u 00007ff62318bf80
//  Fabric!Data::TStore::Store<KSharedPtr<KString>,KSharedPtr<KBuffer> >::TryGetValueAsync$_ResumeCoro$2 [C:\__w\1\s\src\prod\src\data\tstore\Store.h @ 1040]:
//> u 0x7ff623035ee0
//  Fabric!Data::TStore::Store<KSharedPtr<KString>,KSharedPtr<KBuffer> >::ConditionalGetAsync$_ResumeCoro$2 [C:\__w\1\s\src\prod\src\data\tstore\Store.h @ 846]:
//> u 0x7ff62210b9f0
//  Fabric!<lambda_82983005e362cd54ae843770683bcb01>$_ResumeCoro$2::operator() [C:\__w\1\s\src\prod\src\Store\TSReplicatedStore.cpp @ 540]:
function unique_coroutine_frames(coro_fn_addres, first_n, call_stack_depth, dll_base_start, dll_base_end) {
    if (coro_fn_addres.startsWith("0x")) {
        coro_fn_addres = coro_fn_addres.substr(2);
    }

    dll_base_start = parseInt(dll_base_start, 16);
    dll_base_end = parseInt(dll_base_end, 16);

    var parents = find_all_coro_frames(coro_fn_addres, first_n);
    var fn_stacks = new Map();
    for (let i = 0; i < parents.length; ++i) {
        var parent  = parents[i];
        // log("> " + parent.co_address + " " + parent.fn_address);
        var stack = walk_parent_chain(parent, call_stack_depth, dll_base_start, dll_base_end);
        var fn_stack = stack.reduce(function(acc, s) { return acc + "," + s.fn_address; }, "");

        if (fn_stacks.has(fn_stack)) {
            fn_stacks.set(fn_stack, fn_stacks.get(fn_stack) + 1);
        } else {
            fn_stacks.set(fn_stack, 1);
        }
    }

    log("Printing Map.\nMap size: " + fn_stacks.size);
    for (const [key, value] of fn_stacks) {
        log(key + " => " + value);
    }

    return fn_stacks;
}

// coro_pattern   : (String) example: Fabric!*ConditioanlGetAsync*_ResumeCoro$2
// see doc for `unique_coroutine_frames` for other parameters.
function all_unique_coroutine_frames(coro_pattern, first_n, call_stack_depth, dll_base_start, dll_base_end) {
    var lines = exec("x " + coro_pattern);

    for (line of lines) {
        if (!line) {
            continue;
        }

        var splits = line.split(' ');

        var fn_address = splits[0];
        var fn_name = line.substr(fn_address.length);

        fn_address = fn_address.replace('`', '');

        log("Finding unique_coroutine_frames for " + fn_address + " " + fn_name);
        unique_coroutine_frames(fn_address, first_n, call_stack_depth, dll_base_start, dll_base_end);
    }
}

function log(x) {
    host.diagnostics.debugLog(x + "\n")
}

function exec(cmdstr) {
    log("Executing: " + cmdstr);
    return host.namespace.Debugger.Utility.Control.ExecuteCommand(cmdstr);
}

function is_valid_address(address) {
    return address > 0x100000; // todo: should be some high value;
}

function is_valid_function_address(address, dll_base_start, dll_base_end) {
    return address >= dll_base_start && address <= dll_base_end;
}

function find_all_coro_frames(coro_fn_addres, first_n) {
    // Used 0x40 to reach the coroutine_handle address where address of function is stored.
    // dq gives value at that location.
    var lines = exec("!mex.fel -x \"dq 0x${@#Line}+0x40 L1\"  !mex.head -n " + first_n + " !mex.cut -f 5 !mex.grep busy !ext.heap -srch " + coro_fn_addres);

    // exepcted format of lines is array of
    //          <coroutine_handle_memory_address> <coroutine_function_address>
    var parent_coro_frames = [];
    for (line of lines) {
        if (!line) {
            continue;
        }

        var splits = line.split(" ");
        var parent_coro_address = splits[0].replace('`','');
        var parent_fn_address = splits[2].replace('`','');

        if (parent_fn_address !== coro_fn_addres) {
            continue;
        }

        // log(parent_fn_address + " == " + coro_fn_addres);
        parent_coro_frames.push({co_address: parseInt(parent_coro_address, 16), fn_address: parent_fn_address});
    }

    return parent_coro_frames;
}

function walk_parent_chain(child, call_stack_depth, dll_base_start, dll_base_end) {
    if (call_stack_depth <= 0) {
        return [];
    }

    var co_address = child.co_address;
    var heap_adress = co_address - 0x40;
    var parent_co_ref_addres = heap_adress + 0x10;

    // since we don't know when to stop walking up the frame,
    // make some good guesses by checking if memory addresses look valid or not.
    if (!is_valid_address(parent_co_ref_addres)) {
        // log("not a valid addres " + parent_co_ref_addres);
        return [];
    }

    try
    {
        // log("parent_co_ref_addres.toString(16): 0x" + parent_co_ref_addres.toString(16));
        try
        {
            var parent_coro_address_str = host.memory.readMemoryValues(parent_co_ref_addres, 1, 8);
        }
        catch(ex)
        {
            // log("first: "+ ex);
            return [];
        }

        var parent_coro_address = parseInt(parent_coro_address_str, 16);
        var parent_fn_address = host.memory.readMemoryValues(parent_coro_address, 1, 8);

        if (!is_valid_address(parent_coro_address) || !is_valid_function_address(parseInt(parent_fn_address, 16), dll_base_start, dll_base_end)) {
            return [child];
        }

        // log("  > " + parent_coro_address_str + " " + parent_fn_address);
        var stack = walk_parent_chain({co_address: parent_coro_address, fn_address: parent_fn_address}, call_stack_depth - 1, dll_base_start, dll_base_end);
        stack.push(child);
        return stack;
    }
    catch (ex)
    {
        // log("second: " + ex);
    }

    return [child];
}
