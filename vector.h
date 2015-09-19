#ifndef VECTOR_H
#define VECTOR_H

#define VECTOR_INITIAL_CAPACITY 100

// Define a vector type
typedef struct {
	int size;		// slots used so far
	int capacity;	// total available slots
	void **data;	// array of integers we're storing
} vector_t;

void vector_init(vector_t *vector);

void vector_append(vector_t *vector, void *value);

void *vector_get(vector_t *vector, int index);

void vector_set(vector_t *vector, int index, void *value);

void vector_double_capacity_if_full(vector_t *vector);

void vector_free(vector_t *vector);

#endif // VECTOR_H
