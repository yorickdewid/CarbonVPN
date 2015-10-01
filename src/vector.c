#include <stdio.h>
#include <stdlib.h>
#include "vector.h"

static void vector_expand(vector_t *vector) {
	if (vector->size >= vector->capacity) {
		// double vector->capacity and resize the allocated memory accordingly
		vector->capacity *= 2;
		vector->data = realloc(vector->data, sizeof(void *) * vector->capacity);
	}
}

void vector_rebuild(vector_t *vector, int capacity) {
	int i;
	vector_t *tmp = (vector_t *)calloc(1, sizeof(vector_t));

	vector_init(tmp, capacity);
	for (i=0; i<vector->size; ++i) {
		if (vector->data[i])
			vector_append(tmp, vector->data[i]);
	}

	vector_free(vector);
	vector_init(vector, capacity);
	for (i=0; i<tmp->size; ++i) {
		vector_append(vector, tmp->data[i]);
	}

	free(tmp);
}

void vector_init(vector_t *vector, int capacity) {
	// initialize size and capacity
	vector->size = 0;
	vector->capacity = capacity;

	// allocate memory for vector->data
	vector->data = calloc(vector->capacity, sizeof(void *));
}

void vector_append(vector_t *vector, void *value) {
	// make sure there's room to expand into
	vector_expand(vector);

	// append the value and increment vector->size
	vector->data[vector->size++] = value;
}

void *vector_get(vector_t *vector, int index) {
	if (index >= vector->size || index < 0) {
		printf("Index %d out of bounds for vector of size %d\n", index, vector->size);
		exit(1);
	}
	return vector->data[index];
}

void vector_set(vector_t *vector, int index, void *value) {
	// zero fill the vector up to the desired index
	while (index >= vector->size) {
		vector_append(vector, 0);
	}

	// set the value at the desired index
	vector->data[index] = value;
}

void vector_free(vector_t *vector) {
	free(vector->data);
}