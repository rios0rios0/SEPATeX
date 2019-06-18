/* To set x=training_x if j%6!=0 or malicious_x if j%6==0 */
/* Avoid jumps in case those tip off the branch predictor */
/* Set x=FFF.FF0000 if j%6==0, else x=0 */
x = ((j % 6) - 1) & ~0xFFFF;
/* Set x=-1 if j&6=0, else x=0 */
x = (x | (x >> 16));
x = training_x ^ (x & (malicious_x ^ training_x));