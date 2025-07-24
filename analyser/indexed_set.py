from typing import TypeVar, Generic, Optional, Iterator

T = TypeVar('T')

class IndexedSet(Generic[T]):
    """A set-like container that assigns auto-incrementing IDs to unique items."""

    def __init__(self):
        self._items: dict[int, T] = {}  # id -> item
        self._ids: dict[T, int] = {}    # item -> id
        self._next_id = 0

    def add(self, item: T) -> int:
        """Add item and return its ID (new or existing)"""
        if item in self._ids:
            return self._ids[item]

        item_id = self._next_id
        self._items[item_id] = item
        self._ids[item] = item_id
        self._next_id += 1
        return item_id

    def __getitem__(self, item_id: int) -> T:
        """Get item by ID"""
        return self._items[item_id]

    def get_id(self, item: T) -> Optional[int]:
        """Get ID of existing item, returns None if not found"""
        return self._ids.get(item)

    def __contains__(self, item: T) -> bool:
        """Check if item is in set"""
        return item in self._ids

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[T]:
        """Iterate over items"""
        return iter(self._items.values())

    def values(self) -> Iterator[T]:
        """Iterate over items"""
        return iter(self._items.values())

    def items(self) -> Iterator[tuple[int, T]]:
        """Iterate over (id, item) pairs"""
        return iter(self._items.items())

    def ids(self) -> Iterator[int]:
        """Iterate over IDs"""
        return iter(self._items.keys())

    def clear(self):
        """Remove all items"""
        self._items.clear()
        self._ids.clear()
        self._next_id = 0