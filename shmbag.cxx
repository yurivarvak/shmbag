
#include <atomic>
#include <fstream>
#include <string>
#include <memory>
#include <map>
#include <set>
#include <queue>
#include <string>
#include <condition_variable>
#include <unordered_set>
#include <chrono>
#include <mutex>
#include <thread>
#include <functional>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <shmbag.h>

#include <iostream>  // for debug

using namespace std;

// UUID stuff
//#define USE_BTK
#ifdef USE_BTK

#include <btkuniid.h>
static inline bool operator< (const UniIdT& lhs, const UniIdT& rhs)
{ return btkUniIdCompare(&lhs, &rhs) < 0; }

static bool str2uuid(const char *str, UniIdT &id)
{
  if (!str) return false;
  UniIdT lid;
  if (btkUniIdParseString(&lid, str, (size_t) -1, 0) != BTK_E_OK)
    return false;
  id = lid;
  return true;
}

static string uuid2str(const UniIdT &id)
{
  char str[80] = "";
  btkUniIdFormat(str, sizeof(str), NULL, &id, UNIID_T_FMT_STRING, FALSE);
  return string(str);
}

#else // UUID via Boost

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
typedef boost::uuids::uuid UniIdT;
static UniIdT NULL_UNIID_T = boost::uuids::nil_uuid();
static bool btkUniIdIsNull(const UniIdT *id)
{ return id->is_nil(); }

static bool str2uuid(const char *str, UniIdT &id)
{
  if (!str) return false;
  UniIdT lid;
  try {
    string s(str);
    lid = boost::uuids::string_generator()(s); 
  } catch(...) {
    return false;
  }
  if (lid.version() == boost::uuids::uuid::version_unknown)
    return false;
  id = lid;
  return true;
}

static string uuid2str(const UniIdT &id)
{
  return boost::uuids::to_string(id);
}

#endif

// Boost stuff
#define BOOST_DATE_TIME_NO_LIB
#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

using namespace boost::interprocess;

typedef unsigned page_t;

#define PAGESIZE 512 //(mapped_region::get_page_size())

static page_t s2p(int64_t size)
{
  assert(size >= 0);
  int64_t p = size / PAGESIZE;
  if (size % PAGESIZE)
    p++;
  assert(p < INT_MAX);
  return (page_t)p;
} 

static int64_t p2s(page_t pages)
{
  return (int64_t)pages * PAGESIZE;
}

static int64_t alignsize(int64_t size)
{
  return p2s(s2p(size));
}

static mapped_region shmapabs(const file_mapping *file, int64_t ofs, int64_t size)
{
  assert(file);
  assert(ofs >= 0);
  assert(size > 0);
  assert(size < UINT_MAX);
  return mapped_region(*file, read_write, (offset_t)ofs, size_t(size));
}

static mapped_region shmappage(const file_mapping *file, page_t addr, page_t n_pages = 1)
{
  assert(n_pages > 0);
  return shmapabs(file, p2s(addr), p2s(n_pages));
}

struct shmblock
{
  UniIdT  id;
  page_t  address;   // absolute offset in pages
  page_t  capacity;  // capacity in pages
};

static inline bool operator< (const shmblock& lhs, const shmblock& rhs)
{
  return lhs.address < rhs.address;
}

struct shmblock_header : public shmblock
{
  int64_t size;      // current size
};

static void mgr_service_loop(shmbag_mgr_t mgr);
static void mgr_unlink_item(shmbag_mgr_t mgr, page_t addr);
static mapped_region *mapmemblock(shmbag_mgr_t mgr, int64_t ofs);
static mapped_region *mapmemblock(const file_mapping *shm_file, int64_t ofs, int64_t size = 0);

struct shmbag_item
{
  mapped_region *memregion;
  shmbag_mgr    *owner;
  page_t        address;   // absolute offset in pages

  shmbag_item(shmbag_mgr_t mgr, page_t addr); // shmbag_mgr specific constructor
  shmbag_item(const file_mapping &shm_file, int64_t ofs) : owner(0), address(0)
  {
    assert(ofs % PAGESIZE == 0);
    memregion = mapmemblock(&shm_file, ofs);
  }
  ~shmbag_item()
  {
    close();
    if (owner)
      mgr_unlink_item(owner, address);
  }
  int close()
  {
    if (memregion)
    {
      delete memregion;
      memregion = 0;
    }
	return 0;
  }

  int64_t get_offset()
  {
    return p2s(owner ? address : get_header()->address);
  }
  UniIdT get_id()
  {
    return get_header()->id;
  }
  int64_t get_size()
  {
    return get_header()->size;
  }
  int64_t get_capacity()
  {
    assert(get_header()->capacity > 0);
    return p2s(get_header()->capacity) - sizeof(shmblock_header);
  }
  char *get_ptr()
  {
    return (char *)(get_header() + 1);
  }

  int read(int64_t lofs, int64_t size, char *data)
  {
    int64_t to_read = get_size() - lofs;
    if (to_read < 0)  // out of bounds
      return -1;
    
    if (to_read > size)
      to_read = size;

    assert(to_read <= INT_MAX);
    memcpy(data, get_ptr(), to_read);

    return to_read;
  }

  // will not write on insufficient capacity - return -1
  int write(int64_t lofs, int64_t size, const char *data)
  {
    int64_t newsize = lofs + size;
    if (newsize > get_capacity())
      return -1;
    assert(size <= INT_MAX);
    memcpy(get_ptr() + lofs, data, size);
    get_header()->size = newsize;
    return size;
  }
  int append(int64_t size, const char *data)
  {
    return write(get_size(), size, data);
  }
  shmblock_header *get_header()
  {
    mapshm();
    return (shmblock_header *)memregion->get_address();
  }

private:
  void mapshm()
  {
    if (memregion)
      return;
    assert(owner && address);
    memregion = mapmemblock(owner, p2s(address));
	auto hdr = get_header();
	assert(hdr->address == address);
	assert(hdr->capacity > 0);
	assert(hdr->size >= 0);
  }
};

struct shfile_ref
{
  shfile_ref(file_mapping *f, mutex *m) : file(f), mux(m) {}
  ~shfile_ref() { mux->unlock(); }
  file_mapping *file;
private:
  mutex        *mux;
};

typedef std::shared_ptr<shfile_ref> shfile_ptr;

struct shmdevice
{
  string mapped_file;
  page_t psize;
  shmdevice(const char *path) : mapped_file(path), psize(0), file(0)
  {
    fstream f(mapped_file, ios::out | ios::binary | ios::in);
    if (!f.fail())
    {
      f.seekp(0, ios::end);
      psize = (page_t)(f.tellp() / PAGESIZE);
      f.close();
	  file = new file_mapping(mapped_file.c_str(), read_write);
    }
  }

  ~shmdevice() { delete file; }

  bool grow(int64_t incr)
  {
    if (incr == 0)
      return true;
	const int64_t MB4 = 4 * 1024 * 1024;
	incr = alignsize(incr > MB4 ? incr : MB4);
    unmapfile();
    fstream f(mapped_file, ios::out | ios::binary | ios::in);
	assert(!f.fail());
    f.seekp(incr, ios::end) << '\0';
    f.close();
    mapfile();
    psize += s2p(incr);
    return true;
  }

  bool resize(int64_t new_size, bool reset = false)
  {
    if (reset)
    {
      unmapfile();
      fstream f(mapped_file, ios::out | ios::binary | ios::trunc);
      f.close();
      mapfile();
      psize = 0;
    }

    page_t nb = s2p(new_size);
    if (nb == psize)
      return true;

    assert(nb > psize && "truncate not yet supported");

    return grow(p2s(nb - psize));
  }

  shfile_ptr get_file()
  {
    file_mux.lock();
    if (!file)
      file = new file_mapping(mapped_file.c_str(), read_write);
    return make_shared<shfile_ref>(file, &file_mux);
  }
private:
  file_mapping *file;
  mutex         file_mux;

  void mapfile()
  {
    assert(!file);
    file = new file_mapping(mapped_file.c_str(), read_write);
    file_mux.unlock();
  }
  void unmapfile()
  {
    file_mux.lock();
    if (file)
    {
      delete file;
      file = 0;
    }
  }
};

struct control_header
{
  int table_cap;
};

static unsigned initial_bag_block_capacity()
{
  return 2 * 1024;  // enough capacity for nK blocks
}
static page_t initial_bag_size()
{
  const unsigned num_blocks = initial_bag_block_capacity();
  const unsigned pages_per_block = 1;
  return s2p((int64_t)num_blocks * sizeof(shmblock)) + num_blocks * pages_per_block;
}

typedef function<void()> func;

struct shmbag_mgr
{
  // mapping info
  shmdevice      device; // storage device
  mapped_region *control_table; // map of control & allocation table

  // indexing data
  set<shmblock>       blocks;  // managed memory blocks sorted by address
  map<UniIdT, page_t> id_to_addr; // map of named blocks

  // concurrency control
  thread             service;  // service thread
  atomic<bool>       running;  // service is running
  queue<func>        requests; // request queue
  mutex              mux;      // request queue mutex
  condition_variable signal;   // inter-thread notificaitons

  // in flight items
  unordered_multiset<page_t> inflight_items;

  shmbag_mgr(const char *path) : device(path), control_table(0), running(false) {}

  int open(bool reset)
  {
    if (reset || device.psize < initial_bag_size())
    {
      int64_t sz = (int64_t)initial_bag_size() * PAGESIZE;
      device.resize(sz, true);
      int64_t tblsz = (int64_t)initial_bag_block_capacity() * sizeof(shmblock);
      shfile_ptr shf = device.get_file();
	  auto h = shmapabs(shf->file, 0, tblsz + sizeof(control_header));
      control_header *hdr = (control_header *)h.get_address();
      hdr->table_cap = initial_bag_block_capacity();
      memset(hdr + 1, 0, tblsz);
    }

    assert(control_table == 0);
    int tblcap = 0;
    shfile_ptr shf = device.get_file();
    { // get control table size
      auto h = shmappage(shf->file, 0);
      tblcap = ((control_header *)h.get_address())->table_cap;
    }
    assert(tblcap > 0);
    int64_t sz = (int64_t)tblcap * sizeof(shmblock) + sizeof(control_header);
    control_table = new mapped_region(shmapabs(shf->file, 0, sz));

    // read memory blocks
    for (int i = 0; i < control_table_cap(); i++)
      if (get_blks()[i].address)
        blocks.insert(get_blks()[i]);
    // update indexes
    for (auto &b : blocks)
      id_to_addr[b.id] = b.address;

    // start service
    service = thread(mgr_service_loop, this);
    while (!running) this_thread::yield();
    
    return 0;
  }

  int close()
  {
    this_thread::sleep_for(chrono::milliseconds(100)); // TODO: better way to clear request queue
    running = false;
    service.join();
    assert(control_table);
    delete control_table;
    control_table = 0;
    blocks.clear();
	return 0;
  }

  shmbag_item_t acquire_item(const UniIdT &id)
  {
    assert(service.get_id() == this_thread::get_id());
    auto i = id_to_addr.find(id);
    return i == id_to_addr.end() ? 0 : construct_item(i->second);
  }
  
  int move_block(page_t source, page_t target) // returns number of pages copied
  {
    assert(source && target);
	if (source == target)
	  return 0;
	
	shmblock query = { NULL_UNIID_T, source, 0 };
    auto blk = blocks.find(query);
    assert(blk != blocks.end());
    shmblock *shmblk = get_blk_w_addr(source, distance(blocks.begin(), blk));
	assert(shmblk);
	
	shfile_ptr shf = device.get_file();
	auto src = shmappage(shf->file, source, shmblk->capacity);
	auto tgt = shmappage(shf->file, target, shmblk->capacity);
	memmove(tgt.get_address(), src.get_address(), p2s(shmblk->capacity));
	memset(src.get_address(), 0, sizeof(shmblock_header));
	
	shmblk->address = ((shmblock *)tgt.get_address())->address = target;  // update address
	
	blocks.erase(blk);
	blocks.insert(*shmblk);
	if (!btkUniIdIsNull(&shmblk->id)) // if id is not null - update index
      id_to_addr[shmblk->id] = shmblk->address;
  
    return (int)shmblk->capacity;
  }

  page_t alloc(const UniIdT &id, int64_t size)
  {
    assert(service.get_id() == this_thread::get_id());
    assert(id_to_addr.find(id) == id_to_addr.end());

    shmblock *newblock = get_blk_w_addr(0, blocks.size()); // find free slot
	if (!newblock)  // no available slots
	{
	  if (!extend_table_cap())  // can't extend - not possible to alloc
	    return 0;
	  newblock = get_blk_w_addr(0, blocks.size());
	  assert(newblock);
	}
	
	page_t fs_addr = get_free_space_addr();
	page_t min_cap = (size > 0) ? s2p(size + sizeof(shmblock_header)) : 1;
	page_t av_cap = device.psize - fs_addr;
	
	if (av_cap < min_cap) // need to grow shmem file
	{
	  cout << "alloc: grow file from " << device.psize << " to " << device.psize + min_cap - av_cap << "\n";
	  if (!device.grow(p2s(min_cap - av_cap)))
	    return 0;
	}
	
	page_t des_cap = av_cap / 3;
	page_t cap = (size > 0 || min_cap > des_cap) ? min_cap : des_cap;
	
    newblock->id = id;
    newblock->address = fs_addr;
    newblock->capacity = cap;

    // update block header
    init_block_header(newblock->address, newblock->id, newblock->capacity, 0);

    blocks.insert(*newblock);
    if (!btkUniIdIsNull(&id)) // record valid block id
      id_to_addr[id] = newblock->address;

    return newblock->address;
  }

  page_t realloc(page_t addr, int64_t new_size)
  {
    assert(service.get_id() == this_thread::get_id());
    shmblock query = { NULL_UNIID_T, addr, 0 };
    auto blk = blocks.find(query);
    if (blk == blocks.end())
      return 0; // addr not found
    page_t new_cap = s2p(new_size + sizeof(shmblock_header));
    if (blk->capacity >= new_cap) // no need to realloc
      return addr;

    UniIdT id = blk->id;
    page_t new_addr = alloc(NULL_UNIID_T, new_size); // alloc with null id
    if (new_addr)
    { // copy data & free previous block
      shfile_ptr shf = device.get_file();
      shmbag_item from(*shf->file, addr*PAGESIZE), to(*shf->file, new_addr*PAGESIZE);
      int bytes = to.write(0, from.get_size(), from.get_ptr());
      assert(from.get_size() == bytes);
      memset(from.get_header(), 0, sizeof(shmblock_header));
      from.close();
      free(addr);
      set_item_id(&to, id);
    }
    
    return new_addr;
  }

  shmbag_item_t realloc_item(page_t addr, int64_t new_size)
  {
    page_t new_addr = realloc(addr, new_size);
    return new_addr ? construct_item(new_addr) : 0;
  }

  void free(page_t addr) // doesn't clear out block header
  {
    shmblock query = { NULL_UNIID_T, addr, 0 };
    auto blk = blocks.find(query);
    assert(blk != blocks.end());
    shmblock *shmblk = get_blk_w_addr(addr, distance(blocks.begin(), blk));
    assert(shmblk);
    if (!btkUniIdIsNull(&blk->id)) // if id is not null - remove from index
      id_to_addr.erase(blk->id);
    memset(shmblk, 0, sizeof(shmblock));
    blocks.erase(blk);
  }

  shmbag_item_t alloc_or_acquire(const UniIdT &id, int64_t size)
  {
    shmbag_item_t item = acquire_item(id);
    if (!item) // not found
    { // need to allocate
      page_t addr = alloc(id, size);
      item = addr ? construct_item(addr) : 0;
    }
    return item;
  }

  void set_item_id(shmbag_item_t item, const UniIdT &newid)
  {
    assert(service.get_id() == this_thread::get_id());
    assert(id_to_addr.find(newid) == id_to_addr.end()); // make sure it isn't there yet
    shmblock_header *hdr = item->get_header();
    shmblock query = { NULL_UNIID_T, hdr->address, 0 };
    auto blk = blocks.find(query);
    assert(blk != blocks.end());
    shmblock *shmblk = get_blk_w_addr(hdr->address, distance(blocks.begin(), blk));
    assert(shmblk); // must be
    if (!btkUniIdIsNull(&blk->id)) // if old id is not null - remove from index
      id_to_addr.erase(blk->id);
    blocks.erase(blk);
    hdr->id = shmblk->id = newid;
    blocks.insert(*shmblk);
    if (!btkUniIdIsNull(&newid)) // if new id is not null - add to index
      id_to_addr[newid] = hdr->address;
  }

  shmbag_item_t construct_item(page_t addr)
  {
    assert(service.get_id() == this_thread::get_id());
    shmbag_item_t item = new shmbag_item(this, addr);
    inflight_items.insert(addr); // record item
    return item;
  }

  void unlink_item(page_t addr)
  {
    assert(service.get_id() == this_thread::get_id());
    auto i = inflight_items.find(addr);
    assert(i != inflight_items.end());
    inflight_items.erase(i);
	if (inflight_items.find(addr) == inflight_items.end()) // last reference
	{
	  shmblock *blk = get_blk_w_addr(addr);
	  if (blk)  // if not - address not longer valid 
	  { // truncate capacity to match the size
	    shfile_ptr shf = device.get_file();
	    auto h = shmappage(shf->file, addr);
	    shmblock_header *hdr = (shmblock_header *)h.get_address();
	    page_t new_cap = s2p(hdr->size + sizeof(shmblock_header));
	    assert(hdr->capacity >= new_cap);
	    if (hdr->capacity > new_cap)
		{
		  shmblock query = { NULL_UNIID_T, addr, 0 };
          auto b = blocks.find(query);
          assert(b != blocks.end());
		  blocks.erase(b);
		  blk->capacity = hdr->capacity = new_cap;
		  blocks.insert(*blk);
		}
	  }
	}
  }

  int control_table_cap()
  {
    assert(control_table);
    return ((control_header *)control_table->get_address())->table_cap;
  }
  
  bool extend_table_cap()
  {
    auto first_blk = blocks.begin();
	if (first_blk->address == 0 ||
	    inflight_items.find(first_blk->address) != inflight_items.end())
	  return false;

	page_t free_addr = get_free_space_addr();
	
	if (device.psize < free_addr + first_blk->capacity) // need to grow shmem file
      if (!device.grow(p2s(free_addr + first_blk->capacity - device.psize)))
	    return false;
	
	int old_cap = control_table_cap();
	int new_cap = old_cap + (int)(p2s(first_blk->capacity) / sizeof(shmblock));

    shfile_ptr shf = device.get_file();
	delete control_table;
	control_table = new mapped_region(shmappage(shf->file, 0, first_blk->address + first_blk->capacity));
	auto copy = shmappage(shf->file, free_addr, first_blk->capacity);
	shmblock *old_blk = (shmblock *)((char *)control_table->get_address() + p2s(first_blk->address));
	shmblock *new_blk = (shmblock *)copy.get_address();
	memcpy(new_blk, old_blk, p2s(first_blk->capacity));
	memset(old_blk, 0, p2s(first_blk->capacity));
	
	shmblock *blk_slot = get_blk_w_addr(first_blk->address, 0);
	assert(blk_slot);
	blk_slot->address = new_blk->address = free_addr;
	
	blocks.erase(first_blk);
	blocks.insert(*new_blk);
	if (!btkUniIdIsNull(&new_blk->id)) // if id is not null - update index
      id_to_addr[new_blk->id] = new_blk->address;
    
	((control_header *)control_table->get_address())->table_cap = new_cap;
	
	return true;
  }

  shmblock *get_blks()
  {
    assert(control_table);
    return (shmblock *)((control_header *)control_table->get_address() + 1);
  }

  shmblock *get_blk_w_addr(page_t addr, int start_idx = -1)
  {
    if (start_idx < 0 && addr)
	{ // looking for real address & would like to estimate location
      shmblock query = { NULL_UNIID_T, addr, 0 };
      auto blk = blocks.find(query);
      if (blk == blocks.end())
	    return 0;
	  start_idx = distance(blocks.begin(), blk);
    }
	
    start_idx = start_idx < 0 ? 0 : start_idx;
    int table_max = control_table_cap();
    int end_idx = table_max + start_idx;
    assert((int64_t)table_max + start_idx <= INT_MAX); // just in case...
    for (int i = start_idx; i < end_idx; i++)
      if (get_blks()[i % table_max].address == addr)
        return get_blks() + (i % table_max);
    return 0; // not found
  }

  page_t get_free_space_addr()
  {
    if (blocks.empty())
      return s2p((int64_t)control_table_cap() * sizeof(shmblock) + sizeof(control_header));
    auto last = blocks.rbegin();
    return last->address + last->capacity;
  }

  void init_block_header(page_t addr, const UniIdT &id, page_t cap, int64_t size)
  {
    shfile_ptr shf = device.get_file();
	auto h = shmappage(shf->file, addr);
    shmblock_header *hdr = (shmblock_header *)h.get_address();
    hdr->address = addr;
    hdr->capacity = cap;
    hdr->id = id;
    hdr->size = size;
  }
  
  // maintenance stuff
  unsigned maint_slot_idx;
  void do_maint_slots()
  {
    if (blocks.empty())
	  return;
	  
	if (control_table_cap() < blocks.size() * 2)  
	{ // capacity to be double current num blocks
	  extend_table_cap();
	  return;
	}
	
	maint_slot_idx = (maint_slot_idx < blocks.size()) ? maint_slot_idx : 0;
	shmblock *next = 0;
	for (int i = 0; i < 1024; i++)
	{
	  shmblock *cur = get_blks() + maint_slot_idx;
	  if (maint_slot_idx < blocks.size() - 1 || !cur->address)
	  { // there is at least one more used slot
	    if (!next || next == cur)
	      next = cur + 1;
	    while (!next->address) next++;  // find next used slot
	  
	    if (!cur->address || cur->address > next->address) 
	      swap(*cur, *next);
	  }
      maint_slot_idx++;
	  if (maint_slot_idx == blocks.size())
	    break;
	}
  }
  
  page_t last_compact_addr;
  void do_maint_blocks()
  {
    if (blocks.empty())
	  return;
	for (int i = 0; i < 1024; i++)
	{
	  auto blk = blocks.upper_bound({ NULL_UNIID_T, last_compact_addr, 0 });
	  if (blk == blocks.end())
	  {
	    last_compact_addr = 0;
	    break;
  	  }
	  last_compact_addr = blk->address;
	  if (blk == blocks.begin()) // first item
	  {
	    if (inflight_items.find(blk->address) == inflight_items.end())
		  i += move_block(blk->address, s2p((int64_t)control_table_cap() * sizeof(shmblock) + sizeof(control_header)));
	  }
	  auto nx = next(blk);
	  if (nx != blocks.end())
	  { // shift next item to the end of the current one
	    if (inflight_items.find(nx->address) == inflight_items.end())
		  i += move_block(nx->address, blk->address + blk->capacity);
	  }
	}
  }
  
  void do_maint_devsize()
  {
    if (blocks.empty())
	  return;
	  
    const int64_t MB = 1024 * 1024;
	const int64_t GB = 1024 * MB;
    const int64_t desired_size = 4 * GB;
	int64_t total = p2s(device.psize) - (control_table_cap() * sizeof(shmblock)) - sizeof(control_header);
	int64_t est_free = total;

	if (blocks.size() < 100)  // calc used space
	  for (auto b : blocks) est_free -= p2s(b.capacity);
	else { // estimate free space
	  page_t paddr = get_free_space_addr();
	  est_free = p2s(device.psize - paddr);
	  auto blk = blocks.rbegin();
	  for (int i = 0; i < 20 && blk != blocks.rend(); i++, blk++)
	  {
	    assert(paddr >= blk->address + blk->capacity);
	    est_free += p2s(paddr - blk->address - blk->capacity);
		paddr = blk->address;
	  }
	}
	assert(est_free >= 0);
	int ratio = (int)(est_free ? total / est_free : 1000);
	if (ratio > 10 || (total < desired_size && inflight_items.empty() && ratio > 4))  // loads of 90% or 75%
	{
	  device.grow(4 * MB);
	  //cout << "do_maint_devsize: grow total/est_free/inflight " << total << "/"<< est_free <<"/"<< inflight_items.empty() << "\n";
	} /*
	else
	  cout << "do_maint_devsize: nogrow total/est_free/inflight " << total << est_free << inflight_items.empty() << "\n"; */
  }

  // make a request to service thread
  void call(func &req)
  {
    lock_guard<mutex> g(mux);
    requests.push(req);
    signal.notify_one();
  }
};

shmbag_item::shmbag_item(shmbag_mgr_t mgr, page_t addr) : owner(mgr), address(addr), memregion(0)
{
  assert(mgr);
  assert(addr);
  assert(owner->service.get_id() == this_thread::get_id());
}

static mapped_region *mapmemblock(const file_mapping *shm_file, int64_t ofs, int64_t size)
{
  if (size <= 0)  // need to find out
  {
    auto h = shmapabs(shm_file, ofs, sizeof(shmblock_header));
	size = p2s(((shmblock_header *)h.get_address())->capacity);
  }
  return new mapped_region(shmapabs(shm_file, ofs, size));
}

static mapped_region *mapmemblock(shmbag_mgr_t mgr, int64_t ofs)
{
  page_t cap, addr = s2p(ofs);
  atomic<bool> done(false);
  func fn = [&]() { 
    shmblock query = { NULL_UNIID_T, addr, 0 };
    auto blk = mgr->blocks.find(query);
	assert(blk != mgr->blocks.end());
	cap = blk->capacity;
	done = true; 
  };
  mgr->call(fn);
  while (!done) this_thread::yield();
  
  shfile_ptr shf = mgr->device.get_file();
  return mapmemblock(shf->file, ofs, p2s(cap));
}

static void mgr_service_loop(shmbag_mgr_t mgr)
{
  mgr->running = true;
  unique_lock<mutex> mlock(mgr->mux);
  bool timedout = false;
  int maint_task = 0;
  const int max_task = 2;
while (mgr->running) {
  auto ttw = chrono::milliseconds(timedout ? 1 : 0);
  timedout = (mgr->signal.wait_for(mlock, ttw) == cv_status::timeout);
  if (mgr->requests.empty() && !timedout) // spurious
    continue;
  while (!mgr->requests.empty()) // process pending requests
  {
    auto req = mgr->requests.front();
    mgr->requests.pop();
    req();
  }
  switch (maint_task++)
  {
    case 0: mgr->do_maint_slots(); break;
	case 1: mgr->do_maint_blocks(); break;
	case 2: if (1) mgr->do_maint_devsize(); // fallthrough
	default: maint_task = (maint_task < max_task) ? maint_task : 0;
  }
}}

static void mgr_unlink_item(shmbag_mgr_t mgr, page_t addr)
{
  func fn = [=]() { mgr->unlink_item(addr); };
  mgr->call(fn);
}

// TODO: handle exceptions in functions & lambdas below

/* manager protocol */
shmbag_mgr_t shmbag_mgr_open(const char *path, int reset)
{
  shmbag_mgr_t mgr = new shmbag_mgr(path);
  if (mgr->open(reset) != 0) { delete mgr; mgr = 0; }
  return mgr;
}

int shmbag_mgr_close(shmbag_mgr_t mgr)
{
  mgr->close();
  delete mgr;
  return 0;
}

shmbag_item_t shmbag_mgr_item_acquire(shmbag_mgr_t mgr, const char *item_id)
{
  UniIdT id;
  if (!str2uuid(item_id, id))
    return 0;
  shmbag_item_t result = 0;
  atomic<bool> done(false);
  func fn = [&]() { result = mgr->acquire_item(id); done = true; };
  mgr->call(fn);
  while (!done) this_thread::yield();
  return result;
}

shmbag_item_t shmbag_mgr_item_acquire_or_alloc(shmbag_mgr_t mgr, const char *item_id, int64_t size)
{
  UniIdT id;
  if (!str2uuid(item_id, id))
    id = NULL_UNIID_T;
  shmbag_item_t result = 0;
  atomic<bool> done(false);
  func fn = [&]() { result = mgr->alloc_or_acquire(id, size); done = true; };
  mgr->call(fn);
  while (!done) this_thread::yield();
  return result;
}

int shmbag_mgr_item_realloc(shmbag_mgr_t mgr, shmbag_item_t item, int64_t new_size)
{
  assert(item->owner == mgr);
  int result = 0;
  atomic<bool> done(false);
  func fn = [&]() {
    page_t old_addr = item->address;
    page_t new_addr = mgr->realloc(old_addr, new_size);
    if (!new_addr) // error
      result = -1;
    else if (old_addr != new_addr)
    { // reallocation was done - need to update item
      item->close();
	  auto i = mgr->inflight_items.find(old_addr);
      assert(i != mgr->inflight_items.end());
      mgr->inflight_items.erase(i);
      mgr->inflight_items.insert(new_addr);
      item->address = new_addr;
    }
    done = true;
  };
  mgr->call(fn);
  while (!done) this_thread::yield();
  return result;
}

int shmbag_mgr_item_set_id(shmbag_mgr_t mgr, shmbag_item_t item, const char *new_id)
{
  UniIdT id;
  if (!str2uuid(new_id, id))
    return -1;
  atomic<bool> done(false);
  func fn = [&]() { mgr->set_item_id(item, id); done = true; };
  mgr->call(fn);
  while (!done) this_thread::yield();
  return 0;
}

/* consumer protocol */
shmbag_item_t shmbag_item_get(const char *path, int64_t ofs)
{
  auto file = file_mapping(path, read_write);
  return new shmbag_item(file, ofs);
}

/* common protocol */
int shmbag_item_free(shmbag_item_t item)  /* for mgr items will unlink a reference */
{
  delete item;
  return 0;
}
int shmbag_item_close(shmbag_item_t item)
{
  item->close();
  return 0;
}
int shmbag_item_read(shmbag_item_t item, int64_t lofs, int64_t size, char *data)
{
  return item->read(lofs, size, data);
}
int shmbag_item_write(shmbag_item_t item, int64_t lofs, int64_t size, const char *data)
{
  return item->write(lofs, size, data);
}
int shmbag_item_append(shmbag_item_t item, int64_t size, const char *data)
{
  return item->append(size, data);
}
int64_t shmbag_item_get_size(shmbag_item_t item)
{
  return item->get_size();
}
int64_t shmbag_item_get_capacity(shmbag_item_t item)
{
  return item->get_capacity();
}
char *shmbag_item_get_ptr(shmbag_item_t item)
{
  return item->get_ptr();
}
int shmbag_item_get_id(shmbag_item_t item, char *id_buf)
{
  UniIdT id = item->get_id();
  if (btkUniIdIsNull(&id))
    return -1;
  if (id_buf)
  {
    string s = uuid2str(id);
    strcpy(id_buf, s.c_str());
  }
  return 0;
}
int64_t shmbag_item_get_offset(shmbag_item_t item)
{
  return item->get_offset();
}
