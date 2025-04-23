/*
Title: Junk Code Insertion
Note: This technique simply involves inserting meaningless functions or operations."
*/

// This function is JUNK
int GetNumber() {
	int a = 8;
	int b = 18;
	int c = 2;
	return a + b / c;
}

void JunkCodeInsersion() {
	// The real code here
	// ...

	// JUNK CODE ----------------
	int a = 0;
	int b = 0;
	a = a + b;
	b = a - b;
	if (a > b) {
		a = 1;
	}
	else {
		b = 1;
	}
	int c = a * b;
	if (c == GetNumber()) {
		c = 2;
	}
	// ---------------------------

	// The real code here
	// ...
}

int main() {
	JunkCodeInsersion();
	return 0;
}