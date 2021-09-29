# Running external programs using a shim

This repository contains C# source code for a command-line application intended to run another application (the target). It can be used to provide a .exe which runs a .bat file, for example. The .exe might be in a PATH location whereas the target file isn't, avoiding the proliferation of directories needed on PATH. Shims in Chocolatey run this way, but have a major drawback in that if the target program spawns one or more child processes, the Chocolatey shim doesn't exit until all of the child processes exit. This is undesirable in certain scenarios, e.g. when using Gradle (which spawns a long-lived daemon process).

This shim avoids that problem by using the Jobs API which is part of Windows.

At present, the target program is configured into the application as a string resource. This is not ideal, but it means a single .exe can contain everything required and there's no need to worry about separate configuration files.

The plan is to have a separate application which, when invoked with the target program, uses this project as a basis to generate the desired shim .exe.

