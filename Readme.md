# Windbg scripts

## coroutines

### unique_coroutine_frames:
```
Groups all coroutine frames for a coroutine function into unique stack walks.
This helps in finding what all coroutines are present in process/dump.
This is a best effort system. The output will mostly be good but can have some noise as
we don't know when to stop walking up the coroutine parent frames.
parameters:
coro_fn_address  : (String) Address of coroutine function for which you want to find all stack frames.
                   You can get this value from output of `x exe_or_dll_name!*class_name*func_name*_ResumeCoro$2`.
                   This needs to be hex address.
first_n          : (Int) Look at first n heaps containing coro_fn_address.
call_stack_depth : (Int) Depth to go down in call stack. Start from low numbers like `3`.
dll_base_start   : (Long) start address of functions above which only we consider coroutine walk to continue.
dll_base_end     : (Long) end address of functions under which we consider coroutine walk to continue.
                   You can get dll_base_start/end from e.g. `lmDf m exe_or_dll_name`

example usage:
> dx @$scriptContents.unique_coroutine_frames("00007ff62318bf80", 8, 3, 0x00007ff621310000, 0x00007ff624210000)
Printing Map.
Map size: 1
00007ff62318bf80,0x7ff623035ee0,0x7ff62210b9f0, => 8
> dx @$scriptContents.print_stack_from_addresses("00007ff62318bf80,0x7ff623035ee0,0x7ff62210b9f0,")
exe_or_dll!namespace1::fn1$_ResumeCoro$2 [src_path1 @ 1040]:
exe_or_dll!namespace1::fn2$_ResumeCoro$2 [src_path2 @ 846]:
exe_or_dll!<lambda_82983005e362cd54ae843770683bcb01>$_ResumeCoro$2::operator() [src_path3 @ 540]:
```

### walk_coroutine_chain:
```
// Walks the coroutine chain starting from child to the parent in async call stack.
// coro_frame_address : (Int) address of child coroutine_frame from where to start the async stack walk.
// see doc for `unique_coroutine_frames` for other parameters.
// example usage:
// > dx @$scriptContents.walk_coroutine_chain("365840500768", 4, 0x00007ff621310000, 0x00007ff624210000)
//
// You can get coroutine frame address from below command:
//    > !mex.fel -x "dq 0x${@#Line}+0x40 L1" !mex.head -n <limit_to_n_output> !mex.cut -f 5 !mex.grep busy !ext.heap -srch <coroutine_func_address>
```

### Others:
Please check the source file for documentation.

1. all_unique_coroutine_frames
1. print_stack_from_addresses

## RCW

### Dump all rcws. Limit by `!head -n 10`
```
> !grep -r "IUnknown pointer|Managed object" !mex.fel -x "!dumprcw /d 0x${@#Line}" !cut -f 2 !grep RCW !mex.fel -x "!dumpobj /d 0x${@#Line}" !head -n 10 !DumpHeap -short -type System.__ComObject
Managed object:             000001fd2c6df1f0
IUnknown pointer:           000002017a70d080
Managed object:             000001fd2c6e5a48
IUnknown pointer:           000002017942f810
...
```