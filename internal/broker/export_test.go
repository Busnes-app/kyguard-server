package broker

// SetReceiptBatch shrinks the receipt batch for a test; the returned func restores it.
func SetReceiptBatch(n int) func() {
	old := receiptBatch
	receiptBatch = n
	return func() { receiptBatch = old }
}
