"""Feature modules: the tools the assistant can use.

So far: ``portfolio``, which lists, records and removes holdings;
``link_analysis``, which checks a link's text for signs of phishing;
``launcher``, which opens one of a fixed list of Apple's applications;
``calendar``, which lists upcoming events and deadlines, read-only; and
``security_posture``, which reports whether this Mac's built-in protections
are switched on; ``process_overview``, which reports what is running and
what is using the most processor and memory; and ``network_overview``, which
reports which of the user's programs use the network.

Planned: the dependency scan and the security update check.

Boundary: a module runs only when ``potato.security`` hands it a validated
call. Modules never run directly from model output.
"""
