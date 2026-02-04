# Implementation Notes

## Design

Main: Spawn other threads.
Thread_Rx: Ingests vectors of packets and parse up-to IP layer
Thread_ReAssemble: IPv4 Reassembly -> Merged with Thread_Rx unless more performance is required.
Thread_Classify: Hyperscan to search payload and increment counters.
Thread_print: Print stats periodically. -> Merged with main thread.

## Drops

[TODO]

- where drops occur
- why drops occur

## IPv4 Re-Assembly

[TODO]

- how re-assembly is implemented

## `mbuf` Life-Cycle

[TODO]

- mbuf lifecycle decisions

## AI involvement

| S.No. | Tool Type | Name | Generated Content in | Methodology / Involvement level |
| -- | -- | --- | --- | ----- |
| 1. | Chatbot | ChatGPT 5.2 | main.c | Generate a simple skeleton DPDK app to start working |
| 2. | Chatbot | DeepSeek | CMakeLists.txt | Convert Makefile from DPDK/examples to CMakeLists.txt |
| 3. | Chatbot | ?? | None | Asked some details about hyperscan not clear from online documentation |
| 4. | Chatbot | Gemini 3 | None | Had a discussion for performance of some literal pattern matching search implementations. Mainly hyperscan vs `memmem()`/`strstr()` vs `bash` vs pcre2 etc. |
| 5. | Chatbot | ChatGPT 5.2 | test_pkt_gen.py | A scapy script to generate IP fragmented packets, with embedded strings |
| 6. | Chatbot | Gemini 3 | main.c | Discussed about using macros and enum lists for multiple usage types. Learned about the `##` preprocessor string concat and how to use it for this use case. |
| 7. | Chatbot | Gemini 3 | main.c | Summarize compiler output warnings |
| 8. | Chatbot & GitHub Copilot in VSCode | GitHub Co-pilot and DeepSeek | Gave up on doing it completely manually with 1 hour remaining in the deadline and tried to get Co-pilot to help me read payload form the packets |
