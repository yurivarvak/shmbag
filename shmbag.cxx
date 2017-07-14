
#include <atomic>
#include <fstream>
#include <string>
#include <memory>
#include <set>
#include <map>
#include <queue>
#include <string>
#include <condition_variable>
#include <unordered_set>
#include <unordered_map>
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

struct shmblock_index
{
  shmblock_index() : shmem(0) {}
  ~shmblock_index() { addr_to_idx.clear(); addresses.clear(); id_to_addr.clear(); shmem = 0; }
  
  void set_table(void *table)
  {
    assert(!shmem);
	assert(table);
	shmem = table;
	for (unsigned i = 0; i < table_capacity(); i++)
	{
	  shmblock *blk = blktable() + i;
	  if (blk->address)
	  {
	    addr_to_idx[blk->address] = i;
	    addresses.insert(blk->address);
	    put_id(blk->address, blk->id);
	  }
	}
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
  }
  
  void update_table(void *table)
  {
    assert(shmem);
	assert(table);
	shmem = table;
  }
  
  unsigned compact_table(unsigned idx, unsigned size)
  {
    if (addresses.size() == 0)
	  return 0;
    idx = idx < addresses.size() ? idx : 0;
	shmblock *next = 0;
	for (unsigned i = 0; i < size; i++)
	{
	  shmblock *cur = blktable() + idx;
	  if (!cur->address || idx+1 < addresses.size())
	  { // there is at least one more used slot
	    if (!next || next == cur)
	      next = cur + 1;
	    while (!next->address) next++;  // find next used slot
		
		assert(!cur->address || addresses.find(cur->address) != addresses.end());
		assert(addresses.find(next->address) != addresses.end());
		page_t cur_addr = cur->address, next_addr = next->address;
		if (cur_addr == 0 || cur_addr > next_addr)
		{ // swap slots
		  if (cur_addr)
		    addr_to_idx[cur_addr] = next - blktable();
		  addr_to_idx[next_addr] = idx;
		  swap(*cur, *next);
		}
	  }
	  if (++idx == addresses.size())
	    break;
	}
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
	return idx;
  }

  page_t block_addr_by_id(const UniIdT &id)
  {
    auto i = id_to_addr.find(id);
    return i == id_to_addr.end() ? 0 : i->second;
  }
  shmblock *get_block(page_t addr)
  {
	if (addr) // looking for real address
	{
	  auto i = addr_to_idx.find(addr);
	  return i == addr_to_idx.end() ? 0 : blktable() + i->second;
	  // return addr_to_idx.find(addr) != addr_to_idx.end() ? blktable() + addr_to_idx[addr] : 0;
	}
	if (table_capacity() == addresses.size()) // out of empty slots
	  return 0;
	for (unsigned i = addresses.size(); i < table_capacity(); i++)
	  if (blktable()[i].address == 0)
	    return blktable() + i;
	for (unsigned i = 0; i < addresses.size(); i++)
	  if (blktable()[i].address == 0)
	    return blktable() + i;
    return 0;
  }
  shmblock *first_block()  // return first allocated block
  {
    return addresses.begin() == addresses.end() ? 0 : get_block(*addresses.begin());
  }
  shmblock *last_block()  // return last allocated block
  {
    return addresses.rbegin() == addresses.rend() ? 0 : get_block(*addresses.rbegin());
  }
  shmblock *next_block(page_t addr)  // next block with address that is larger than, not equal to
  {
    auto i = addresses.upper_bound(addr);
	return i == addresses.end() ? 0 : get_block(*i);
  }
  unsigned num_blocks()  // number of allocated blocks
  {
    return addresses.size();
  }
  int64_t estimate_frag_space()
  {
    page_t frag_pages = 0;
	auto cur = addresses.rbegin();
	for (int i = 0; i < 1000 && cur != addresses.rend(); i++, cur++)
	{
	  auto nx = next(cur);
	  if (nx == addresses.rend())
	    break;
	  page_t cap = get_block(*nx)->capacity;
	  assert(*cur >= *nx + cap);
	  frag_pages += *cur - *nx - cap;
	}
	return p2s(frag_pages);
  }
  pair<page_t, page_t> find_free_block(page_t size)
  {
	for (auto cur = addresses.rbegin(); cur != addresses.rend(); cur++)
	{
	  auto nx = next(cur);
	  if (nx == addresses.rend())
	    break;
	  page_t pcap = get_block(*nx)->capacity;
	  assert(*cur >= *nx + pcap);
	  page_t fcap = *cur - *nx - pcap;
	  if (fcap >= size)
	    return make_pair(*nx + pcap, fcap);
	}
	return make_pair(0, 0);  // not found
  }
  
  void change_id(page_t addr, const UniIdT &new_id)
  {
    assert(addr);
	auto blk = get_block(addr);
	assert(blk);
    if (!btkUniIdIsNull(&blk->id))
	  id_to_addr.erase(blk->id);
	blk->id = new_id;
	put_id(addr, new_id);
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
  }
  void add_block(shmblock *blk)
  {
    assert(blk >= blktable());
	assert(blk->address);
	assert(addr_to_idx.find(blk->address) == addr_to_idx.end());
	assert(addresses.find(blk->address) == addresses.end());
	unsigned idx = blk - blktable();
	addr_to_idx[blk->address] = idx;
	addresses.insert(blk->address);
	put_id(blk->address, blk->id);
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
  }
  void move_block(page_t old_addr, page_t new_addr)
  {
    assert(old_addr && new_addr);
	assert(addr_to_idx.find(old_addr) != addr_to_idx.end());
	assert(addr_to_idx.find(new_addr) == addr_to_idx.end());
	assert(addresses.find(old_addr) != addresses.end());
	assert(addresses.find(new_addr) == addresses.end());
	auto blk = get_block(old_addr);
	blk->address = new_addr;
	addr_to_idx[new_addr] = addr_to_idx[old_addr];
	addr_to_idx.erase(old_addr);
	addresses.erase(old_addr);
	addresses.insert(new_addr);
	put_id(new_addr, blk->id);
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
  }
  void free_block(page_t addr)
  {
    assert(addr);
	auto blk = get_block(addr);
	assert(blk);
	if (!btkUniIdIsNull(&blk->id))
	  id_to_addr.erase(blk->id);
	addresses.erase(addr);
	addr_to_idx.erase(addr);
	memset(blk, 0, sizeof(shmblock));
	assert(addr_to_idx.size() == addresses.size() && addresses.size() >= id_to_addr.size());
  }
private:
  unordered_map<page_t, unsigned> addr_to_idx;
  set<page_t>                     addresses;
  map<UniIdT, page_t>             id_to_addr;
  void                           *shmem;
  
  shmblock *blktable()
  {
    assert(shmem);
    return (shmblock *)((control_header *)shmem + 1);
  }
  unsigned table_capacity()
  {
    assert(shmem);
    int cap = ((control_header *)shmem)->table_cap;
	assert(cap > 0);
	return (unsigned)cap;
  }
  void put_id(page_t addr, const UniIdT &id)
  {
    assert(addr);
    if (!btkUniIdIsNull(&id))
	  id_to_addr[id] = addr;
  }
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
  shmblock_index blkindex;

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

    blkindex.set_table(control_table->get_address()); // init indexing

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
	return 0;
  }

  shmbag_item_t acquire_item(const UniIdT &id)
  {
    assert(service.get_id() == this_thread::get_id());
	page_t addr = blkindex.block_addr_by_id(id);
    return addr ? construct_item(addr) : 0;
  }
  
  int move_block(page_t source, page_t target) // returns number of pages copied
  {
    assert(source && target);
	if (source == target)
	  return 0;
	
	shfile_ptr shf = device.get_file();
	auto cap = blkindex.get_block(source)->capacity;
	auto src = shmappage(shf->file, source, cap);
	auto tgt = shmappage(shf->file, target, cap);
	memmove(tgt.get_address(), src.get_address(), p2s(cap));
	blkindex.move_block(source, target);
	memset(src.get_address(), 0, sizeof(shmblock_header));  // reset old header
	((shmblock *)tgt.get_address())->address = target;  // update address in header

    return (int)cap;
  }

  page_t alloc(const UniIdT &id, int64_t size)
  {
    assert(service.get_id() == this_thread::get_id());

    shmblock *newblock = blkindex.get_block(0); // find free slot
	if (!newblock)  // no available slots
	{
	  if (!extend_table_cap())  // can't extend - not possible to alloc
	    return 0;
	  newblock = blkindex.get_block(0);
	  assert(newblock);
	}
	
	page_t fs_addr = get_free_space_addr();
	page_t addr = fs_addr;
	page_t min_cap = (size > 0) ? s2p(size + sizeof(shmblock_header)) : 1;
	page_t av_cap = device.psize - fs_addr;
	
	if (av_cap < min_cap) 
	{
	  auto fb = blkindex.find_free_block(min_cap);
	  if (fb.first == 0) // need to grow shmem file
	  {
	    // cout << "alloc: grow file from " << device.psize << " to " << device.psize + min_cap - av_cap << "\n";
	    if (!device.grow(p2s(min_cap - av_cap)))
	      return 0;
	  }
	  else
	  {
	    addr = fb.first;
		av_cap = fb.second;
	  }
	}
	else
	  av_cap /= 16;  // number of concurrent writers multiplied by something, maybe 8?
	
	page_t cap = (size > 0 || min_cap > av_cap) ? min_cap : av_cap;
	
    newblock->id = id;
    newblock->address = addr;
    newblock->capacity = cap;
	blkindex.add_block(newblock);

    // update block header
    init_block_header(newblock->address, newblock->id, newblock->capacity, 0);

    return newblock->address;
  }

  page_t realloc(page_t addr, int64_t new_size)
  {
    assert(service.get_id() == this_thread::get_id());
    shmblock query = { NULL_UNIID_T, addr, 0 };
    auto blk = blkindex.get_block(addr);
    if (blk == 0)
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
    blkindex.free_block(addr);
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
	blkindex.change_id(item->get_header()->address, newid);
	item->get_header()->id = newid;
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
	  shmblock *blk = blkindex.get_block(addr);
	  if (blk)  // if not - address not longer valid 
	  { // truncate capacity to match the size
	    shfile_ptr shf = device.get_file();
	    auto h = shmappage(shf->file, addr);
	    shmblock_header *hdr = (shmblock_header *)h.get_address();
	    page_t new_cap = s2p(hdr->size + sizeof(shmblock_header));
	    assert(hdr->capacity >= new_cap);
	    if (hdr->capacity > new_cap)
		  blk->capacity = hdr->capacity = new_cap;
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
    auto first_blk = blkindex.first_block();
	if (first_blk == 0 || inflight_items.find(first_blk->address) != inflight_items.end())
	  return false;

	page_t fb_addr = first_blk->address, fb_cap = first_blk->capacity;
	page_t free_addr = get_free_space_addr();
	if (device.psize < free_addr + fb_cap) 
	{
	  auto fb = blkindex.find_free_block(fb_cap);
	  if (fb.first == 0) // need to grow shmem file
	  {
	    // cout << "extend_table_cap: grow file from " << device.psize << " to " << free_addr + fb_cap << "\n";
        if (!device.grow(p2s(free_addr + fb_cap - device.psize)))
	      return false;
	  }
	  else
	    free_addr = fb.first;
	}
	
	move_block(fb_addr, free_addr);  // move first block to the end

    // remap control table & initialize additional table pages
	shfile_ptr shf = device.get_file();
	delete control_table;
	control_table = new mapped_region(shmappage(shf->file, 0, fb_addr + fb_cap));
	char *ct = (char *)control_table->get_address();
	((control_header *)ct)->table_cap = (int)((p2s(fb_addr + fb_cap) - sizeof(control_header)) / sizeof(shmblock));
	memset(ct + p2s(fb_addr), 0, p2s(fb_cap));
	blkindex.update_table(ct);
	
	return true;
  }

  page_t get_free_space_addr()
  {
    auto last = blkindex.last_block();
	if (last)
	  return last->address + last->capacity;
    return s2p((int64_t)control_table_cap() * sizeof(shmblock) + sizeof(control_header));
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
  void do_maint_slots(int iter)
  {
	if (control_table_cap() < blkindex.num_blocks() * 2)  
	{ // capacity to be double current num blocks
	  int i = 0;
	  while (i++ < iter && control_table_cap() < blkindex.num_blocks() * 4 && extend_table_cap()) ;
	  return;
	}
	
	maint_slot_idx = blkindex.compact_table(maint_slot_idx, iter);
  }
  
  page_t last_compact_addr;
  void do_maint_blocks(int iter)
  {
	for (int i = 0; i < iter; i++)
	{
	  shmblock *blk = blkindex.next_block(last_compact_addr);
	  if (!blk)
	  {
	    last_compact_addr = 0;
		do_maint_devsize();
	    break;
  	  }
	  last_compact_addr = blk->address;
	  if (blk == blkindex.first_block()) // first item
	  {
	    if (inflight_items.find(blk->address) == inflight_items.end())
		  i += move_block(blk->address, s2p((int64_t)control_table_cap() * sizeof(shmblock) + sizeof(control_header)));
		blk = blkindex.first_block(); // it might have changed above
	  }
	  auto nx = blkindex.next_block(blk->address);
	  // shift next item to the end of the current one
	  if (nx && inflight_items.find(nx->address) == inflight_items.end())
	    i += move_block(nx->address, blk->address + blk->capacity);
	}
  }
  
  void do_maint_devsize()
  {
    const int64_t MB = 1024 * 1024;
	const int64_t GB = 1024 * MB;
    const int64_t desired_size = 4 * GB;
	int64_t ctab_size = (int64_t)control_table_cap() * sizeof(shmblock) + sizeof(control_header);
	int64_t total = p2s(device.psize) - ctab_size;
	int64_t est_free = total + ctab_size - p2s(get_free_space_addr()) + blkindex.estimate_frag_space();

	assert(est_free >= 0);
	int ratio = (int)(est_free ? total / est_free : 1000);
	if (ratio > 10 || (total < desired_size && inflight_items.empty() && ratio > 5))  // loads of 90% or 80%
	{
	  device.grow(4 * MB);
	  // cout << "do_maint_devsize: grow total/est_free/inflight " << total << "/"<< est_free <<"/"<< inflight_items.empty() << "\n";
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
  func fn = [&]() { cap = mgr->blkindex.get_block(addr)->capacity; done = true; };
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
  int n_runs = 0;

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
  if (timedout || ++n_runs > 1024)
  {
    if (n_runs > 1024)
	  n_runs = 0;
    mgr->do_maint_slots(64);
    mgr->do_maint_blocks(64);
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
  static unordered_map<string, file_mapping *> files;
  static mutex mux;
  
  string s(path);
  lock_guard<mutex> g(mux);
  auto fi = files.find(s);
  
  if (fi == files.end())
  {
    try {
	  files[s] = new file_mapping(path, read_write);
	} catch (...) { return 0; }
	fi = files.find(s);
	assert(fi != files.end());
  }
  
  shmbag_item_t item;
  try {
    item = new shmbag_item(*fi->second, ofs);
  } catch (...) {  // maybe file handle went bad
    delete fi->second;
	files.erase(s);
	try {
	  files[s] = new file_mapping(path, read_write);
	  item = new shmbag_item(*files[s], ofs);
	} catch (...) { return 0; }
  }
  return item;
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
