Mandatory for CS454 and CS654

**Project Title: Encryption and Decryption with AES and RSA**

**Objective:**
- Implement various AES modes of encryption/decryption and compare their error propagation.
- Compare the time consumption of RSA and AES for encryption/decryption.

**I. Introduction**
- The purpose of this project is to explore encryption and decryption techniques using AES and RSA.
- This project is implemented in Python, and it leverages the pycryptodome library for AES encryption, while focusing on the implementation of different AES modes.

**II. AES Encryption and Decryption**

   **A. Part 1: AES Encryption/Decryption with Standard Modes**
   - Implement the following AES modes: ECB, CBC, CFB, OFB, and CTR.
   - Use a library such as pycryptodome for AES encryption and decryption. You do not need to implement the AES algorithm itself.
     - You can use  pycryptodome in ECB mode (including for your ECB implementation ) to achieve a vanilla AES module
     -  For all modes, make sure that your input a message that is larger than a few blocks, so you can make the block and encrypt each block independently. Later, you will see how the error propagates by corrupting one cipher block; hence you will need more than 3.
   - The focus should be on correctly implementing and understanding the various AES modes.
   - Provide code samples for generating a key, encrypting, and decrypting a message for each mode.
   - Include a section on how to prepare a message.
   - Explain the concept and purpose of each mode.

   **B. Part 2: Introducing Errors**
   - Describe how you will introduce errors in the ciphertext (e.g., bit flips).
   - Implement error introduction in your code.
   - Explain what you expect in terms of error propagation.

   **C. Part 3: Error Propagation Analysis**
   - Provide code samples for encrypting and decrypting with errors for each mode.
   - Record and compare how many blocks the errors propagated in each mode.
   - Discuss whether the propagations match your expectations.

**III. RSA Encryption and Decryption**
- Explain the steps to use RSA for encryption and decryption.
- Compare the time consumption of RSA with AES for encryption and decryption. Do a few timed trials.

  - Use similar encryption parameters
  - You can use RSA from pycryptodome
 

**IV. Conclusion**
- Summarize the key findings and lessons learned.
- Discuss any unexpected results.

**V. References**
- Cite the resources and documentation you used for this project.

**VI. Screenshots**
- Include screenshots of code, encryption/decryption in action, and error propagation.

**VII. Code**
- Provide the complete Python code used for the project.
- Include comments for clarity and understanding.

**Grading Rubric Example:**

**Code Quality (30 points)**
- Code runs/compiles and output matches report: 5 points
- Clear and organized code: 5 points
- Proper use of comments and documentation: 10 points
- Correct implementation of AES modes and error propagation: 10 points

**Completeness (30 points)**
- All required AES modes implemented: 10 points
- Error propagation analysis for each mode: 10 points
- Accurate RSA implementation and time comparison: 10 points

**Analysis of Error Propagation (20 points)**
- Accurate analysis of error propagation in each mode: 10 points
- Appropriate discussion of whether propagations matched expectations: 10 points

**Time Comparison (20 points)**
- Correct comparison of time consumption between RSA and AES: 10 points
- Appropriate discussion of results: 10 points

**Total: 100 points**

 

AES in Python: https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.htmlLinks to an external site.