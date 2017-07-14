
#include <string>
#include <chrono>
#include <thread>
#include <iostream>
#include <stdlib.h>
#include "shmbag.h"

using namespace std;

// UUID stuff
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
using namespace boost::uuids;
string get_uuid(int i)
{
  boost::uuids::name_generator g(boost::uuids::nil_uuid());
  boost::uuids::uuid u(g(&i, sizeof(i)));
  return boost::uuids::to_string(u);
}

void print_item(shmbag_item_t item, const char *msg = 0)
{
  char id[80] = "nil";
  shmbag_item_get_id(item, id);
  if (msg)
    cout << msg << " = ";
  cout << "{ item:" << id << 
    ", size:" << shmbag_item_get_size(item) <<
    ", cap:" << shmbag_item_get_capacity(item) << " }\n";
}

bool simple_test()
{
  cout << "\nSimple test:";
  const char *fname = "simple.shmdata";
  shmbag_mgr_t mgr = shmbag_mgr_open(fname, true); assert(mgr);
  string s = get_uuid(100);
  shmbag_item_t item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(!item);
  item = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), 100); assert(item);
  const char *data = "some text";
  int ret = shmbag_item_append(item, strlen(data) + 1, data); assert(ret == strlen(data) + 1);
  print_item(item, "initial item");
  ret = shmbag_item_free(item); assert(ret == 0);
  ret = shmbag_mgr_close(mgr); assert(ret == 0);
  mgr = shmbag_mgr_open(fname, false);
  item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(item);
  ret = shmbag_item_append(item, strlen(data) + 1, data); assert(ret == strlen(data) + 1);
  print_item(item, "after reopen & update");
  ret = shmbag_mgr_item_realloc(mgr, item, 12854); assert(ret == 0);
  print_item(item, "after realloc");
  ret = shmbag_item_free(item); assert(ret == 0);
  shmbag_item_t item2 = shmbag_mgr_item_acquire_or_alloc(mgr, 0, 33893); assert(item);
  const char *data2 = "other text";
  ret = shmbag_item_append(item2, strlen(data2) + 1, data2);assert(ret == strlen(data2) + 1);
  print_item(item2, "nameless item");
  s = get_uuid(101);
  ret = shmbag_mgr_item_set_id(mgr, item2, s.c_str()); assert(ret == 0);
  print_item(item2, "set item name");
  ret = shmbag_item_free(item2); assert(ret == 0);
  item2 = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), 0); assert(item);
  print_item(item2, "reopen renamed item");
  ret = shmbag_item_free(item2); assert(ret == 0);
  ret = shmbag_mgr_close(mgr); assert(ret == 0);
  return true;
}

void large_test()
{
  cout << "\nLarge test:";
  const char *fname = "large.shmdata";
  const int num_blocks = 100000;
  auto start = chrono::system_clock::now();
  shmbag_mgr_t mgr = shmbag_mgr_open(fname, true); assert(mgr);
  for (int i = 0; i < num_blocks; i++)
  {
    string s = get_uuid(i);
    shmbag_item_t item = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), -1); assert(item);
	int ret = shmbag_item_append(item, s.size() + 1, s.c_str()); assert(ret == s.size() + 1);
    ret = shmbag_item_free(item); assert(ret == 0);
  }
  auto mid = chrono::system_clock::now();
  chrono::duration<double> elapsed_seconds = mid - start;
  cout << "alloc " << elapsed_seconds.count() << "s. " << flush;
  for (int i = 0; i < num_blocks; i++)
  {
    string s = get_uuid(i);
    shmbag_item_t item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(item);
    int ret = shmbag_mgr_item_realloc(mgr, item, (num_blocks - i) * 1 + 1); assert(ret == 0);
	assert(!strcmp(shmbag_item_get_ptr(item), s.c_str()));
    shmbag_item_t item2 = shmbag_item_get(fname, shmbag_item_get_offset(item)); assert(item);
	assert(!strcmp(shmbag_item_get_ptr(item2), s.c_str()));
    ret = shmbag_item_free(item2); assert(ret == 0);
    ret = shmbag_item_free(item); assert(ret == 0);
  }
  auto end = chrono::system_clock::now();
  elapsed_seconds = end - mid;
  cout << " realloc " << elapsed_seconds.count() << "s.\n";
  cout << " do nothing test 5s... " << flush;
  this_thread::sleep_for(chrono::seconds(5));
  auto dono = chrono::system_clock::now();
  elapsed_seconds = dono - end;
  cout << "done in " << elapsed_seconds.count() << "s.\n" << flush;
  int ret = shmbag_mgr_close(mgr); assert(ret == 0);
}

void cc_tread_func(shmbag_mgr_t mgr, const char *fname, int thr_num, int i_num)
{
  const int max_thr = 10;
  for (int i = 0; i < i_num; i++)
  {
    string s = get_uuid(i);  // simulate work
	if (i % max_thr != thr_num) // not mine
	  continue;
	shmbag_item_t item = shmbag_mgr_item_acquire_or_alloc(mgr, s.c_str(), i); assert(item);
	shmbag_item_t item2 = shmbag_item_get(fname, shmbag_item_get_offset(item)); assert(item);
	int ret = shmbag_item_append(item2, s.size() + 1, s.c_str()); assert(ret == s.size() + 1);
	assert(!strcmp(shmbag_item_get_ptr(item2), s.c_str()));
	if (!((i - thr_num) % (max_thr * 10)))
	  this_thread::sleep_for(chrono::milliseconds(1)); // simulate work
	ret = shmbag_item_free(item2); assert(ret == 0);
	assert(!strcmp(shmbag_item_get_ptr(item), s.c_str()));
	ret = shmbag_item_free(item); assert(ret == 0);
	item = shmbag_mgr_item_acquire(mgr, s.c_str()); assert(item);
	assert(!strcmp(shmbag_item_get_ptr(item), s.c_str()));
	ret = shmbag_item_free(item); assert(ret == 0);
  }
}

void concurrent_test()
{
  cout << "\nConcurrent test: " << flush;
  const char *fname = "concurrent.shmdata";
  const int num_blocks = 100000;
  const int num_threads = 4;
  auto start = chrono::system_clock::now();
  shmbag_mgr_t mgr = shmbag_mgr_open(fname, true); assert(mgr);
  vector<thread> procs;
  for (int i = 0; i < num_threads; i++)
    procs.push_back(thread(cc_tread_func, mgr, fname, i, num_blocks));
  for (int i = 0; i < num_threads; i++)
    procs[i].join();
  auto end = chrono::system_clock::now();
  chrono::duration<double> elapsed_seconds = end - start;
  cout << num_threads << " threads done in " << elapsed_seconds.count() << "s.\n\n" << flush;  
}

int main()
{
  simple_test();
  large_test();
  concurrent_test();
  return 0;
}
